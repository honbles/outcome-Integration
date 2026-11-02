# Outcome-level configuration: identifying policy-engine semantics

Code and results for the paper **"Identifying Policy-Engine Semantics from Distinguishing Probes: Sound Feasibility and Graded Verification for Outcome-Level Configuration Changes"** (Blessing Honmane, SafeLinx Technology). Preprint: https://doi.org/10.21203/rs.3.rs-11524043/v1

An agent asked to realize an outcome (for example, "permit these flows") on an unfamiliar ordered-rule policy engine has to know how the engine resolves overlapping rules. This repository contains the experiments that test how far sandbox probes can establish that, and what they cannot.

## Layout

```
code/     experiments and checks (Python 3, standard library only)
  aws/    AWS network ACL experiment (not yet run against a real account)
results/  saved output of each run reported in the paper
```

## Requirements

- Python 3.8+, no third-party packages (the `aws/` scripts need `boto3`).
- The `real_engine_*` scripts drive real packet filters and need **root** on a disposable machine or VM. They create network namespaces, flush firewall rulesets and start local servers. Do not run them on a host you care about.

| Script | Needs |
|---|---|
| `real_engine_experiment*.py` (1, 2, 5, 7, 8) | Linux, `ip`, `iptables` (legacy and nft), `nft` |
| `real_engine_experiment3.py`, `real_engine_experiment4.py` | the above plus `nginx` |
| `real_engine_experiment6_pf.py` | OpenBSD or FreeBSD with `pf` |

## Scripts

| Script | What it does | Paper section |
|---|---|---|
| `sanity_checks.py` | Small-instance checks of Theorems 2, 4, 5, 6 (fixed seed) | Appendix |
| `check_insertion_stability.py` | Brute-force check that all eight semantics in H8 are insertion-stable | VII-B |
| `baseline_cost.py` | Probe counts: enumeration vs one probe per cell | VII-A |
| `engine_experiments.py` | Hypothesis class from vendor docs; identification on simulated engines (iptables, pf, AWS NACL, Azure NSG) | VII-B, VII-C |
| `real_engine_experiment.py` | Real Linux netfilter (iptables-legacy, iptables-nft, nft): in-class and out-of-class engines | VII-D |
| `real_engine_experiment2.py` | Part A: out-of-class engines and detection suites. Part B: 2D grid, cell lemma, non-interference | VII-D |
| `real_engine_experiment3.py` | Linux routing (part C) and nginx location matching (part D) | VII-E |
| `real_engine_experiment4.py` | Detection phase on the second family | VII-E |
| `real_engine_experiment5.py` | Detection against engines drawn by a seeded generator | VII-H |
| `real_engine_experiment6_pf.py` | Real OpenBSD pf over loopback | VII-F |
| `real_engine_experiment7_state.py` | Connection-tracking divergence (plain, fresh, stale modes) | VII-G |
| `real_engine_experiment8_scale.py` | Plan check on a 65,536-flow space: cells vs enumeration | VII-A |

`engine_experiments.py` uses simulators of documented behavior. Only the `real_engine_*` scripts measure a real engine. AWS and Azure are simulated in the paper, not measured.

## Running

Run everything from `code/`. Several scripts import `real_engine_experiment.py`, so keep the files together.

```bash
cd code

# no root needed
python3 sanity_checks.py
python3 engine_experiments.py
python3 baseline_cost.py
python3 check_insertion_stability.py

# root needed
sudo python3 real_engine_experiment.py
sudo python3 real_engine_experiment2.py A    # A | B | AB
sudo python3 real_engine_experiment3.py C    # C | D | CD
sudo python3 real_engine_experiment4.py E
sudo python3 real_engine_experiment7_state.py
sudo python3 real_engine_experiment8_scale.py

# on OpenBSD
doas python3 real_engine_experiment6_pf.py
```

The seeded-generator experiment takes options `--seed --engines --sample --mc --only`. The paper's runs used three seeds:

```bash
sudo sh -c 'for s in 1 2 3; do
  python3 -u real_engine_experiment5.py --seed $s --engines 40 --sample 600 --sample4 400 --mc 10000 > run_seed$s.txt 2>&1
done'
```

Seeds run one after another because they share network namespaces. Each finished run ends with a `SUMMARY` line.

## Results

`results/` holds the saved output of the runs reported in the paper, one file per script and part:

| File | Script |
|---|---|
| `sanity_output.txt`, `engine_output.txt` | `sanity_checks.py`, `engine_experiments.py` |
| `check_insertion_stability_output.txt`, `baseline_cost_output.txt` | `check_insertion_stability.py`, `baseline_cost.py` |
| `real_engine_output.txt` | `real_engine_experiment.py` (kernel 6.18, iptables 1.8.10, nftables 1.0.9) |
| `real_engine_output2_partA.txt`, `..._partB.txt` | `real_engine_experiment2.py` |
| `real_engine_output3_partC.txt`, `..._partD.txt` | `real_engine_experiment3.py` |
| `real_engine_output4_partE.txt` | `real_engine_experiment4.py` |
| `real_engine_output5_server_seed{1,2,3}.txt` | `real_engine_experiment5.py` (kernel 6.17, nftables 1.1.5) |
| `real_engine_output6_pf_openbsd.txt` | `real_engine_experiment6_pf.py` (OpenBSD 8.0) |
| `real_engine_output7_state.txt` | `real_engine_experiment7_state.py` |
| `real_engine_output8_scale.txt` | `real_engine_experiment8_scale.py` |

## Limitations

Real measurements cover Linux netfilter (stateless UDP on one hook, connection tracking in one experiment), Linux routing, nginx and OpenBSD pf on loopback, at small scale. The out-of-class engines are our own constructions. See the paper's Limitations section.

## Citation

```
B. Honmane, "Identifying Policy-Engine Semantics from Distinguishing Probes: Sound Feasibility
and Graded Verification for Outcome-Level Configuration Changes," Research Square preprint, 2026.
doi:10.21203/rs.3.rs-11524043/v1
```
