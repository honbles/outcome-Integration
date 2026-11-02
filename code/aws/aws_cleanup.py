#!/usr/bin/env python3
"""Undo aws_setup.py: restore the subnet's original network ACL, delete the experiment ACL, terminate the instance,
delete the security group. Reads aws_state.json from the current directory."""
import json, time, boto3
s = json.load(open("aws_state.json"))
ec2 = boto3.client("ec2", region_name=s["region"])
try: ec2.replace_network_acl_association(AssociationId=s["new_association"], NetworkAclId=s["original_nacl"]); print("original network ACL restored")
except Exception as e: print("ACL restore:", e)
try: ec2.delete_network_acl(NetworkAclId=s["nacl"]); print("experiment ACL deleted")
except Exception as e: print("ACL delete:", e)
try:
    ec2.terminate_instances(InstanceIds=[s["instance"]]); ec2.get_waiter("instance_terminated").wait(InstanceIds=[s["instance"]]); print("instance terminated")
except Exception as e: print("instance:", e)
print("check the EC2 console afterwards: instances, security groups and public IPv4 addresses are billed")
for _ in range(10):
    try: ec2.delete_security_group(GroupId=s["sg"]); print("security group deleted"); break
    except Exception as e: print("security group (retrying):", e); time.sleep(6)
