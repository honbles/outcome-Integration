#!/usr/bin/env python3
"""Create the AWS resources for the network ACL experiment (free-tier sized) and print the run command.

Creates in the default VPC of the chosen region: a security group (UDP 9000-9003 and TCP 8080 from your IP only),
one small EC2 instance that runs aws_receiver.py, and a dedicated network ACL that it associates with the
instance's subnet. It records everything in aws_state.json so aws_cleanup.py can undo it.

Needs: pip install boto3, and AWS credentials in the environment (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY).
WARNING: the dedicated network ACL replaces the ACL of the instance's subnet. Use a fresh account or a quiet default VPC.

Usage: python3 aws_setup.py --region us-east-1 [--my-ip 203.0.113.7] [--instance-type t3.micro]"""
import argparse, json, os, secrets, sys, time, urllib.request
import boto3

ap = argparse.ArgumentParser()
ap.add_argument("--region", required=True)
ap.add_argument("--my-ip", default="", help="public IP of the machine that will run the experiment (auto-detected if omitted)")
ap.add_argument("--instance-type", default="t3.micro")
a = ap.parse_args()
ip = a.my_ip or urllib.request.urlopen("https://checkip.amazonaws.com", timeout=10).read().decode().strip()
cidr = ip + "/32"
ec2 = boto3.client("ec2", region_name=a.region)
ssm = boto3.client("ssm", region_name=a.region)
here = os.path.dirname(os.path.abspath(__file__))
token = secrets.token_hex(8)
state = {"region": a.region, "token": token}
def save(): json.dump(state, open("aws_state.json", "w"), indent=1)   # written after every create, so a crash can still be cleaned up
save()

vpcs = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])["Vpcs"]
if not vpcs: sys.exit("no default VPC in region %s: pick another region, or create one with `aws ec2 create-default-vpc --region %s`" % (a.region, a.region))
vpc = vpcs[0]["VpcId"]
subs = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc]}, {"Name": "default-for-az", "Values": ["true"]}])["Subnets"]
if not subs: sys.exit("the default VPC %s has no default subnet" % vpc)
subnet = sorted(subs, key=lambda s: s["AvailabilityZone"])[0]["SubnetId"]
state.update(vpc=vpc, subnet=subnet); save()
print("default VPC", vpc, "subnet", subnet)

sg = ec2.create_security_group(GroupName="nacl-exp-" + token, Description="network ACL experiment", VpcId=vpc)["GroupId"]
ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[
    {"IpProtocol": "udp", "FromPort": 9000, "ToPort": 9003, "IpRanges": [{"CidrIp": cidr}]},
    {"IpProtocol": "tcp", "FromPort": 8080, "ToPort": 8080, "IpRanges": [{"CidrIp": cidr}]}])
state["sg"] = sg; save()

ami = ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64")["Parameter"]["Value"]
recv = open(os.path.join(here, "aws_receiver.py")).read()
user_data = "#!/bin/bash\ncat > /opt/aws_receiver.py <<'PYEOF'\n%sPYEOF\nnohup python3 /opt/aws_receiver.py %s > /var/log/receiver.log 2>&1 &\n" % (recv, token)
inst = ec2.run_instances(ImageId=ami, InstanceType=a.instance_type, MinCount=1, MaxCount=1, SubnetId=subnet, SecurityGroupIds=[sg],
                         UserData=user_data, TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "nacl-exp"}]}])["Instances"][0]["InstanceId"]
state["instance"] = inst; save()
ec2.get_waiter("instance_running").wait(InstanceIds=[inst])
pub = ec2.describe_instances(InstanceIds=[inst])["Reservations"][0]["Instances"][0].get("PublicIpAddress")
state["receiver_ip"] = pub; save()
print("instance", inst, "public IP", pub)

nacl = ec2.create_network_acl(VpcId=vpc, TagSpecifications=[{"ResourceType": "network-acl", "Tags": [{"Key": "Name", "Value": "nacl-exp"}]}])["NetworkAcl"]["NetworkAclId"]
ec2.create_network_acl_entry(NetworkAclId=nacl, RuleNumber=50, Protocol="6", RuleAction="allow", Egress=False, CidrBlock=cidr, PortRange={"From": 8080, "To": 8080})
ec2.create_network_acl_entry(NetworkAclId=nacl, RuleNumber=100, Protocol="-1", RuleAction="allow", Egress=True, CidrBlock="0.0.0.0/0")
assoc = [x for n in ec2.describe_network_acls(Filters=[{"Name": "association.subnet-id", "Values": [subnet]}])["NetworkAcls"]
         for x in n["Associations"] if x["SubnetId"] == subnet][0]
state.update(nacl=nacl, original_association=assoc["NetworkAclAssociationId"], original_nacl=assoc["NetworkAclId"]); save()
new_assoc = ec2.replace_network_acl_association(AssociationId=assoc["NetworkAclAssociationId"], NetworkAclId=nacl)["NewAssociationId"]
state["new_association"] = new_assoc; save()
print("waiting for the receiver to answer on port 8080 (up to 5 minutes)...")
ok = False
for _ in range(60):
    try:
        urllib.request.urlopen("http://%s:8080/seen?t=%s" % (pub, token), timeout=4).read(); ok = True; break
    except Exception: time.sleep(5)
print("receiver is up" if ok else "WARNING: the receiver did not answer; check that your IP is %s and wait a little longer before running the experiment" % ip)
print("\nsaved aws_state.json. Public IPv4 addresses are billed hourly: run aws_cleanup.py when you are done and check the console.")
print("If your public IP changes during the run, the security group stops admitting your probes: rerun the experiment after fixing it.\nNow run:\n")
print("python3 aws_nacl_experiment.py --region %s --nacl-id %s --receiver %s --token %s" % (a.region, nacl, pub, token))
