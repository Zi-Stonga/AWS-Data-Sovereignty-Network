# AWS Data Sovereignty Network

A hybrid cloud network architecture that enforces data residency boundaries for global
financial institutions across EU, APAC, and US AWS regions.
Built for banks that operate simultaneously under GDPR, MiFID II, DORA, MAS TRM 2021,
APRA CPS 234, NYDFS Part 500, and CCPA, and need to satisfy all of them with a single
network architecture.

---

## The Problem This Solves

A global bank with customers in the EU, Singapore, and the US cannot run a single flat
network. GDPR says EU customer data cannot leave the EEA. MAS TRM says Singapore customer
data must be accessible from within Singapore. DORA says ICT resilience must be tested
and documented. These requirements do not naturally coexist.

The standard answer is process controls: policies, checklists, and training. Regulators
increasingly do not accept this. They want technical evidence that a misconfigured
application or a rogue developer cannot move data across the boundary, not just evidence
that they are not supposed to.

This project includes Service Control Policies, VPC design, and DNS
architecture.

---

## Project Structure

```
src/           Python application code
  config/      Zone enumerations, settings loader, and validation
  iam/         SCP and IAM role generators
  network/     Topology and peering validators, DNS architecture
  compliance/  DORA testing schedule, evidence aggregation
  monitoring/  CloudWatch alarm and Config rule builders

tests/         Unit tests (all pass with pytest, no AWS credentials needed)
  unit/        Mirrors src/ structure, one test file per source file

terraform/     Infrastructure as Code
  modules/     Reusable modules: vpc, scp, tgw, dx, iam, dns, monitoring
  environments/EU, APAC, US environment entrypoints

docs/
  specs/       Architecture, data model, local dev guide
  
```

---

## The Three Zones

**EU Sovereign Zone** covers eu-west-1 (Dublin) and eu-central-1 (Frankfurt). GDPR and
MiFID II data lives here and nowhere else. EU banking VPCs use Virtual Private Gateway
attachments, not Transit Gateway, because TGW transitive routing could otherwise create
a path to a non-EU network. A SCP denies every data-bearing API call outside these two
regions from the EU OU.

**APAC Sovereign Zone** covers ap-southeast-1 (Singapore). A standalone TGW with no
inter-region peering handles intra-zone routing. MAS TRM requires customer data to be
accessible from within Singapore, so no replication to any other region is permitted
for MAS-classified data.

**US Zone** covers us-east-1 and us-east-2. An SCP blocks access to EU PII, GDPR, and
MiFID II S3 buckets from US regions. GLBA and NYDFS Part 500 controls apply here.

Cross-zone communication is allowed only for anonymised analytics, aggregated risk metrics,
non-PII operational data, and SIEM logs with PII stripped before transit. All of these
travel via PrivateLink service endpoints, which expose a named service rather than routing
a CIDR, so there is no network-layer path between zones.

---

## Getting Started

Copy the environment file and fill in your values:

```bash
cp .env.example .env
```

Install dependencies:

```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

Run the test suite:

```bash
pytest
```

All unit tests run without AWS credentials. Integration tests (in tests/integration/)
require credentials and are excluded from the default pytest run.

---

## Deploying

Each sovereign zone is a separate Terraform environment. Deploy them independently
to enforce the account and region boundaries:

```bash
cd terraform/environments/eu
terraform init
terraform plan -var-file=eu.tfvars
terraform apply -var-file=eu.tfvars
```

Repeat for apac and us. Never run a single apply across zones. The environment isolation
is part of the control architecture.

---

## Generating IAM Policies

The Python modules generate the SCP and IAM role definitions programmatically. To produce
JSON policy files for review before Terraform apply:

```bash
python scripts/generate_policies.py
```

This writes policy documents to output/policies/. Review them before committing.
The SCP builder enforces least-privilege constraints and will raise an error if a
generated policy contains a wildcard action on a sensitive resource.

---

## Compliance Evidence

Evidence artifacts for regulatory audit are automated wherever possible:

- Network topology diagrams: auto-generated from AWS Config resource graph weekly
- VPC Flow Log data residency reports: Athena queries confirm no EU PII traffic to non-EU CIDRs
- SCP violation logs: every denial recorded in CloudTrail and forwarded to SIEM
- Macie PII discovery: monthly report, daily scans, DPO portal integration
- S3 Object Lock WORM: GDPR audit logs immutable for 7 years
- AWS Artifact: SOC 2 Type II, ISO 27001, EU Data Protection Addendum on demand

The DORA testing schedule is managed in src/compliance/dora_schedule.py.
check_overdue_tests() surfaces any test that has passed its due date.

---

## Security Notes

The management account is not subject to SCPs applied at the OU level. Access to the
management account must be restricted to named administrators with hardware MFA.

No secrets, account IDs, or credentials belong in this repository. Use .env for local
development and AWS Secrets Manager or Parameter Store for deployed environments.

Dependency versions are pinned in requirements.txt. Run a CVE scan before updating any
dependency.


---

## Regulatory References

- GDPR Articles 44 and 46: personal data transfers outside the EEA
- MiFID II Article 16: investment firm record-keeping obligations
- DORA Articles 24 and 26: digital operational resilience testing
- MAS TRM 2021: Technology Risk Management guidelines
- APRA CPS 234: information security
- NYDFS 23 NYCRR Part 500: cybersecurity requirements for financial services
- CCPA: California Consumer Privacy Act