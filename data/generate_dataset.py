"""
Realistic CloudTrail Dataset Generator with Zero Label Leakage Guarantee (Stage 3).

Generates enterprise-scale AWS CloudTrail telemetry mirroring realistic enterprise
behavior and sophisticated attack simulations (Stratus Red Team / MITRE ATT&CK Cloud Matrix).

Key Design Highlights:
1. Benign Realism & Noise:
   - Contains privilege APIs (legitimate admin, CI/CD, key rotation).
   - Off-hours activity (on-call responders, automated cron, nightly CI/CD).
   - Unfamiliar / new IPs (remote work, roaming VPN, dynamic DHCP).
   - Unfamiliar / new regions (cross-region deployments, DR rehearsals).
   - High API frequency bursts (Terraform, batch queries, automated scanners).
   - Benign errors (session expiry, CLI typos, API throttling).

2. Threat Realism & Stealth:
   - Known IPs (compromised developer laptops, insider threats, stolen local tokens).
   - Known regions (operating in home region to blend into noise).
   - Normal business hours (attacks timed 9am-5pm to evade temporal anomaly alerts).
   - Low frequency / stealth (low-and-slow execution with 1-8 calls/10m).
   - Successful requests (error_status = 0, clean execution).

3. Multi-Event Attack & Benign Sequences:
   - Attack flow: Normal activity / recon -> Suspicious probing -> Privilege escalation action.
   - Benign flow: Discovery / status check -> Parameter inspection -> Legitimate administrative action.

4. Metadata:
   - data_source = 'synthetic'
   - attack_type (detailed attack taxonomy for threats; 'none' for benign)
   - scenario_id (structured scenario tracking)
   - label (0 = benign, 1 = threat)

5. Project Structure & Raw Identifiers:
   - Identifiers kept strictly as metadata, not model features.
   - Existing IAM privilege escalation scope preserved.
"""

import json
import os
import random
from datetime import datetime, timedelta
import pandas as pd
import numpy as np

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "processed")
os.makedirs(OUTPUT_DIR, exist_ok=True)

SEED = 42
random.seed(SEED)
np.random.seed(SEED)

NUM_EVENTS = 14000

# -----------------------------------------------------------------------------
# Enterprise Identities Baseline
# -----------------------------------------------------------------------------
IDENTITIES = {
    "devops_admin": {
        "arn": "arn:aws:iam::123456789012:role/DevOpsAdminRole",
        "type": "AssumedRole",
        "userName": "DevOpsAdminRole",
        "home_regions": ["us-east-1", "us-east-2"],
        "known_ips": ["10.100.4.12", "10.100.4.15", "192.168.10.40"],
        "work_hours": (8, 19),
        "typical_ua": "aws-cli/2.11.0 Python/3.11.2",
    },
    "jenkins_cicd": {
        "arn": "arn:aws:iam::123456789012:role/JenkinsCICDRunner",
        "type": "AssumedRole",
        "userName": "JenkinsCICDRunner",
        "home_regions": ["us-east-1"],
        "known_ips": ["10.200.1.5", "10.200.1.6"],
        "work_hours": (0, 24),
        "typical_ua": "aws-sdk-go/v2.1.0",
    },
    "alice_lead": {
        "arn": "arn:aws:iam::123456789012:user/alice_lead_dev",
        "type": "IAMUser",
        "userName": "alice_lead_dev",
        "home_regions": ["us-east-1"],
        "known_ips": ["192.168.1.50", "192.168.1.51"],
        "work_hours": (9, 18),
        "typical_ua": "AWS Management Console",
    },
    "bob_contractor": {
        "arn": "arn:aws:iam::123456789012:user/bob_contractor",
        "type": "IAMUser",
        "userName": "bob_contractor",
        "home_regions": ["us-east-1"],
        "known_ips": ["192.168.1.88"],
        "work_hours": (10, 17),
        "typical_ua": "AWS Management Console",
    },
    "carol_secops": {
        "arn": "arn:aws:iam::123456789012:user/carol_secops",
        "type": "IAMUser",
        "userName": "carol_secops",
        "home_regions": ["us-east-1", "us-west-2"],
        "known_ips": ["10.50.2.10", "10.50.2.11"],
        "work_hours": (8, 20),
        "typical_ua": "aws-cli/2.11.0 Python/3.11.2",
    },
    "app_service_role": {
        "arn": "arn:aws:iam::123456789012:role/AppBackendServiceRole",
        "type": "AssumedRole",
        "userName": "AppBackendServiceRole",
        "home_regions": ["us-east-1"],
        "known_ips": ["10.10.15.22", "10.10.15.23"],
        "work_hours": (0, 24),
        "typical_ua": "Boto3/1.28.0 Python/3.10.6",
    },
}

ALL_REGIONS = ["us-east-1", "us-east-2", "us-west-2", "eu-west-1", "ap-southeast-1", "sa-east-1"]
ATTACKER_IPS = ["198.51.100.24", "203.0.113.88", "185.220.101.5", "45.154.255.99", "104.244.76.13", "194.26.29.112"]
ATTACKER_UAS = ["python-requests/2.31.0", "Kali-Linux-CloudSploit", "botocore/1.29.0 raw-script", "curl/7.88.1", "Pacu/v1.4.0"]

# 8 Target IAM Privilege Escalation Events
PRIVILEGE_EVENTS = [
    ("iam.amazonaws.com", "AttachUserPolicy"),
    ("iam.amazonaws.com", "PutUserPolicy"),
    ("iam.amazonaws.com", "AttachRolePolicy"),
    ("iam.amazonaws.com", "PutRolePolicy"),
    ("iam.amazonaws.com", "CreateAccessKey"),
    ("iam.amazonaws.com", "UpdateAccessKey"),
    ("sts.amazonaws.com", "AssumeRole"),
    ("iam.amazonaws.com", "PassRole"),
]

NON_PRIVILEGE_EVENTS = [
    ("ec2.amazonaws.com", "DescribeInstances"),
    ("ec2.amazonaws.com", "DescribeSecurityGroups"),
    ("s3.amazonaws.com", "ListBuckets"),
    ("s3.amazonaws.com", "GetObject"),
    ("iam.amazonaws.com", "ListUsers"),
    ("iam.amazonaws.com", "ListRoles"),
    ("sts.amazonaws.com", "GetCallerIdentity"),
]

ATTACK_TAXONOMY = {
    "AttachUserPolicy": "privilege_escalation_user_policy",
    "PutUserPolicy": "inline_policy_injection",
    "AttachRolePolicy": "privilege_escalation_role_policy",
    "PutRolePolicy": "role_inline_policy_backdoor",
    "CreateAccessKey": "rogue_credential_creation",
    "UpdateAccessKey": "credential_activation_abuse",
    "AssumeRole": "unauthorized_role_assumption",
    "PassRole": "pass_role_privilege_escalation",
    "recon": "discovery_reconnaissance",
    "probing": "permission_probing",
}

def generate_base_event(
    is_threat: bool,
    force_event=None,
    force_identity=None,
    force_time=None,
    force_ip_behavior=None,
    force_region_behavior=None,
    force_freq_behavior=None,
    force_error=None,
    attack_type=None,
    scenario_id=None,
):
    """Generates a single granular CloudTrail event with realistic, noisy contextual distributions."""
    ident_key = force_identity if force_identity else random.choice(list(IDENTITIES.keys()))
    ident = IDENTITIES[ident_key]

    if force_event:
        source, name = force_event
    else:
        if random.random() < 0.50:
            source, name = random.choice(PRIVILEGE_EVENTS)
        else:
            source, name = random.choice(NON_PRIVILEGE_EVENTS)

    is_privilege = 1 if (source, name) in PRIVILEGE_EVENTS else 0

    base_date = datetime(2026, 4, 1, 0, 0, 0)
    day_offset = random.randint(0, 30)

    # -------------------------------------------------------------
    # 1. TEMPORAL & WORKING HOURS
    # -------------------------------------------------------------
    if force_time:
        event_time = force_time
        hour = event_time.hour
        is_off_hours = 1 if (hour < 6 or hour > 20) else 0
    else:
        if not is_threat:
            # Benign: mostly work hours, but ~24% off-hours (cron, on-call responders, late CI/CD)
            start_h, end_h = ident["work_hours"]
            if ident_key in ["jenkins_cicd", "app_service_role"] or random.random() < 0.24:
                hour = random.randint(0, 23)
            else:
                hour = random.randint(start_h, min(end_h, 23))
        else:
            # Threat: 52% off-hours, but 48% daytime (blending into work hours)
            if random.random() < 0.52:
                hour = random.choice([0, 1, 2, 3, 4, 5, 21, 22, 23])
            else:
                hour = random.randint(8, 18)

        is_off_hours = 1 if (hour < 6 or hour > 20) else 0
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        event_time = base_date + timedelta(days=day_offset, hours=hour, minutes=minute, seconds=second)

    # -------------------------------------------------------------
    # 2. IP ADDRESS (KNOWN VS NEW)
    # -------------------------------------------------------------
    if force_ip_behavior is not None:
        is_new_ip = 1 if force_ip_behavior == "new" else 0
        source_ip = random.choice(ATTACKER_IPS) if is_new_ip else random.choice(ident["known_ips"])
    else:
        if not is_threat:
            # Benign: ~22% new IP (work-from-home DHCP change, hotel/airport VPN, roaming)
            if random.random() < 0.22:
                source_ip = f"172.16.{random.randint(1, 50)}.{random.randint(2, 250)}"
                is_new_ip = 1
            else:
                source_ip = random.choice(ident["known_ips"])
                is_new_ip = 0
        else:
            # Threat: 62% new attacker IP, 38% KNOWN IP (compromised dev machine, insider threat)
            if random.random() < 0.62:
                source_ip = random.choice(ATTACKER_IPS)
                is_new_ip = 1
            else:
                source_ip = random.choice(ident["known_ips"])
                is_new_ip = 0

    # -------------------------------------------------------------
    # 3. AWS REGION (HOME VS FOREIGN)
    # -------------------------------------------------------------
    if force_region_behavior is not None:
        is_new_region = 1 if force_region_behavior == "new" else 0
        foreign_regions = [r for r in ALL_REGIONS if r not in ident["home_regions"]]
        region = random.choice(foreign_regions) if (is_new_region and foreign_regions) else random.choice(ident["home_regions"])
    else:
        if not is_threat:
            # Benign: ~18% new region (cross-region deployments, DR rehearsals, global S3 access)
            if random.random() < 0.18:
                foreign_regions = [r for r in ALL_REGIONS if r not in ident["home_regions"]]
                region = random.choice(foreign_regions) if foreign_regions else ident["home_regions"][0]
                is_new_region = 1
            else:
                region = random.choice(ident["home_regions"])
                is_new_region = 0
        else:
            # Threat: 46% foreign region, 54% HOME REGION (operating in home region to avoid regional alerts)
            foreign_regions = [r for r in ALL_REGIONS if r not in ident["home_regions"]]
            if random.random() < 0.46 and foreign_regions:
                region = random.choice(foreign_regions)
                is_new_region = 1
            else:
                region = random.choice(ident["home_regions"])
                is_new_region = 0

    # -------------------------------------------------------------
    # 4. CALL FREQUENCY (10-MINUTE WINDOW)
    # -------------------------------------------------------------
    if force_freq_behavior is not None:
        frequency_10m = force_freq_behavior
    else:
        if not is_threat:
            # Benign: usually 1-10 calls, but 20% automated Terraform / CI/CD bursts (14-40 calls)
            if ident_key in ["jenkins_cicd", "devops_admin"] and random.random() < 0.25:
                frequency_10m = random.randint(14, 40)
            elif random.random() < 0.12:
                frequency_10m = random.randint(12, 28)
            else:
                frequency_10m = random.randint(1, 9)
        else:
            # Threat: 62% bursty (15-55 calls), but 38% STEALTHY LOW-AND-SLOW (1-8 calls)
            if random.random() < 0.62:
                frequency_10m = random.randint(15, 55)
            else:
                frequency_10m = random.randint(1, 8)

    # -------------------------------------------------------------
    # 5. USER AGENT
    # -------------------------------------------------------------
    if not is_threat:
        # Benign: mostly typical UA, occasional script/SDK
        if random.random() < 0.10:
            user_agent = "Python/3.11 aiobotocore/2.5.0"
        else:
            user_agent = ident["typical_ua"]
    else:
        # Threat: 52% attacker tool/script, 48% legitimate identity UA
        if random.random() < 0.52:
            user_agent = random.choice(ATTACKER_UAS)
        else:
            user_agent = ident["typical_ua"]

    # -------------------------------------------------------------
    # 6. TARGET USER MISMATCH
    # -------------------------------------------------------------
    if is_privilege:
        if not is_threat:
            # Benign: ~24% admin configuring another user/role
            target_user_is_different = 1 if (ident_key in ["devops_admin", "carol_secops"] and random.random() < 0.28) else 0
        else:
            # Threat: ~58% targeting other entities
            target_user_is_different = 1 if random.random() < 0.58 else 0
    else:
        target_user_is_different = 0

    # -------------------------------------------------------------
    # 7. ERROR STATUS & MFA
    # -------------------------------------------------------------
    if force_error is not None:
        error_status = 1 if force_error else 0
    else:
        if not is_threat:
            # Benign error rate: ~14% (session expiry, typo in CLI parameter, resource missing)
            error_status = 1 if random.random() < 0.14 else 0
        else:
            # Threat: 38% error (probing), 62% SUCCESSFUL REQUEST (no error)
            error_status = 1 if random.random() < 0.38 else 0

    if not is_threat:
        mfa_authenticated = 1 if (ident["type"] == "IAMUser" and random.random() < 0.78) else 0
    else:
        mfa_authenticated = 1 if random.random() < 0.12 else 0

    # -------------------------------------------------------------
    # 8. METADATA TAGS
    # -------------------------------------------------------------
    if attack_type is None:
        if is_threat:
            attack_type = ATTACK_TAXONOMY.get(name, "cloud_intrusion_threat")
        else:
            attack_type = "none"

    if scenario_id is None:
        scenario_id = f"syn-std-{'th' if is_threat else 'bg'}-{random.randint(1000, 9999)}"

    return {
        "event_time": event_time.isoformat() + "Z",
        "event_source": source,
        "event_name": name,
        "aws_region": region,
        "source_ip": source_ip,
        "user_agent": user_agent,
        "identity_arn": ident["arn"],
        "identity_type": ident["type"],
        "user_name": ident["userName"],
        "is_new_ip_for_identity": is_new_ip,
        "is_new_region_for_identity": is_new_region,
        "event_hour": hour,
        "is_off_hours": is_off_hours,
        "call_frequency_10m": frequency_10m,
        "target_user_is_different": target_user_is_different,
        "is_privilege_action": is_privilege,
        "error_status": error_status,
        "mfa_authenticated": mfa_authenticated,
        "data_source": "synthetic",
        "attack_type": attack_type,
        "scenario_id": scenario_id,
        "is_threat": 1 if is_threat else 0,
    }

# -----------------------------------------------------------------------------
# Multi-Event Sequence Generators
# -----------------------------------------------------------------------------
def generate_attack_sequence(seq_id_num: int):
    """
    Generates a realistic 3-step multi-event attack sequence:
    Step 1: Normal activity / initial discovery (recon)
    Step 2: Suspicious probing / enumeration (probing)
    Step 3: High-impact privilege escalation action (exploit)
    """
    seq_id = f"syn-seq-threat-{seq_id_num:04d}"
    ident_key = random.choice(["alice_lead", "bob_contractor", "devops_admin", "carol_secops"])
    ident = IDENTITIES[ident_key]

    base_date = datetime(2026, 4, 1, 0, 0, 0)
    day = random.randint(0, 28)
    
    # Decide if sequence is stealthy (daytime, known IP) or loud (off-hours, new IP)
    is_stealth = random.random() < 0.45
    if is_stealth:
        hour = random.randint(9, 17)
        ip_behavior = "known"
        region_behavior = "home"
    else:
        hour = random.choice([1, 2, 3, 22, 23])
        ip_behavior = "new"
        region_behavior = "new" if random.random() < 0.50 else "home"

    t1 = base_date + timedelta(days=day, hours=hour, minutes=random.randint(5, 20), seconds=random.randint(0, 59))
    t2 = t1 + timedelta(minutes=random.randint(3, 8), seconds=random.randint(10, 50))
    t3 = t2 + timedelta(minutes=random.randint(2, 6), seconds=random.randint(10, 50))

    priv_evt = random.choice(PRIVILEGE_EVENTS)
    attack_name = ATTACK_TAXONOMY.get(priv_evt[1], "privilege_escalation")

    # Step 1: Normal / Recon
    e1 = generate_base_event(
        is_threat=True,
        force_event=("sts.amazonaws.com", "GetCallerIdentity"),
        force_identity=ident_key,
        force_time=t1,
        force_ip_behavior=ip_behavior,
        force_region_behavior=region_behavior,
        force_freq_behavior=random.randint(1, 6),
        force_error=False,
        attack_type="discovery_reconnaissance",
        scenario_id=seq_id,
    )

    # Step 2: Suspicious Probing
    e2 = generate_base_event(
        is_threat=True,
        force_event=random.choice([("iam.amazonaws.com", "ListUsers"), ("iam.amazonaws.com", "ListRoles"), ("s3.amazonaws.com", "ListBuckets")]),
        force_identity=ident_key,
        force_time=t2,
        force_ip_behavior=ip_behavior,
        force_region_behavior=region_behavior,
        force_freq_behavior=random.randint(6, 18),
        force_error=(random.random() < 0.35),
        attack_type="permission_probing",
        scenario_id=seq_id,
    )

    # Step 3: Privilege Action
    e3 = generate_base_event(
        is_threat=True,
        force_event=priv_evt,
        force_identity=ident_key,
        force_time=t3,
        force_ip_behavior=ip_behavior,
        force_region_behavior=region_behavior,
        force_freq_behavior=random.randint(10, 35) if not is_stealth else random.randint(2, 8),
        force_error=(random.random() < 0.25),
        attack_type=attack_name,
        scenario_id=seq_id,
    )

    return [e1, e2, e3]

def generate_benign_sequence(seq_id_num: int):
    """
    Generates a realistic 3-step benign multi-event administrative or pipeline sequence:
    Step 1: Status check / discovery
    Step 2: Resource enumeration
    Step 3: Legitimate privilege action (e.g. policy attach, key rotation, assume role)
    """
    seq_id = f"syn-seq-benign-{seq_id_num:04d}"
    ident_key = random.choice(["devops_admin", "jenkins_cicd", "carol_secops", "alice_lead"])
    ident = IDENTITIES[ident_key]

    base_date = datetime(2026, 4, 1, 0, 0, 0)
    day = random.randint(0, 28)

    # Benign sequence timing (mostly business hours or scheduled nightly CI/CD)
    if ident_key == "jenkins_cicd" or random.random() < 0.25:
        hour = random.randint(0, 23)
    else:
        hour = random.randint(8, 18)

    t1 = base_date + timedelta(days=day, hours=hour, minutes=random.randint(5, 25), seconds=random.randint(0, 59))
    t2 = t1 + timedelta(minutes=random.randint(2, 5), seconds=random.randint(10, 50))
    t3 = t2 + timedelta(minutes=random.randint(1, 4), seconds=random.randint(10, 50))

    priv_evt = random.choice(PRIVILEGE_EVENTS)

    # Step 1: Pre-flight check
    e1 = generate_base_event(
        is_threat=False,
        force_event=("ec2.amazonaws.com", "DescribeInstances") if ident_key != "carol_secops" else ("iam.amazonaws.com", "ListRoles"),
        force_identity=ident_key,
        force_time=t1,
        force_freq_behavior=random.randint(2, 12),
        force_error=False,
        attack_type="none",
        scenario_id=seq_id,
    )

    # Step 2: Resource Inspection
    e2 = generate_base_event(
        is_threat=False,
        force_event=random.choice([("ec2.amazonaws.com", "DescribeSecurityGroups"), ("s3.amazonaws.com", "ListBuckets"), ("iam.amazonaws.com", "ListUsers")]),
        force_identity=ident_key,
        force_time=t2,
        force_freq_behavior=random.randint(3, 16),
        force_error=(random.random() < 0.08),
        attack_type="none",
        scenario_id=seq_id,
    )

    # Step 3: Legitimate Privilege Action
    e3 = generate_base_event(
        is_threat=False,
        force_event=priv_evt,
        force_identity=ident_key,
        force_time=t3,
        force_freq_behavior=random.randint(4, 25),
        force_error=(random.random() < 0.06),
        attack_type="none",
        scenario_id=seq_id,
    )

    return [e1, e2, e3]

# -----------------------------------------------------------------------------
# Main Dataset Builder
# -----------------------------------------------------------------------------
def build_dataset():
    print(f"[*] Generating {NUM_EVENTS} realistic CloudTrail events with anti-leakage contextual grounding...")

    events = []

    # 1. Generate Multi-Event Sequences (Attack & Benign)
    num_sequences = 300  # 300 threat sequences + 300 benign sequences = 1,800 sequence events
    for i in range(num_sequences):
        events.extend(generate_attack_sequence(i + 1))
        events.extend(generate_benign_sequence(i + 1))

    print(f"  [+] Multi-event sequences generated: {len(events)} events ({num_sequences} threat & {num_sequences} benign sequences)")

    # 2. Balanced Privilege Events (Guaranteed 50% benign / 50% threat per privilege API)
    per_priv_count = 350
    for priv_evt in PRIVILEGE_EVENTS:
        for _ in range(per_priv_count):
            events.append(generate_base_event(is_threat=False, force_event=priv_evt))
            events.append(generate_base_event(is_threat=True, force_event=priv_evt))

    print(f"  [+] Balanced privilege events generated: {per_priv_count * 2 * len(PRIVILEGE_EVENTS)} events across 8 IAM actions")

    # 3. Fill Remaining Events to Target Dataset Size with Balanced Non-Privilege & Baseline Mix
    remaining = NUM_EVENTS - len(events)
    if remaining > 0:
        benign_remaining = int(remaining * 0.65)
        threat_remaining = remaining - benign_remaining
        for _ in range(benign_remaining):
            events.append(generate_base_event(is_threat=False))
        for _ in range(threat_remaining):
            events.append(generate_base_event(is_threat=True))

    random.shuffle(events)
    df = pd.DataFrame(events)

    # Reorder columns logically: metadata first, features, then label
    column_order = [
        "event_time",
        "event_source",
        "event_name",
        "aws_region",
        "source_ip",
        "user_agent",
        "identity_arn",
        "identity_type",
        "user_name",
        "is_new_ip_for_identity",
        "is_new_region_for_identity",
        "event_hour",
        "is_off_hours",
        "call_frequency_10m",
        "target_user_is_different",
        "is_privilege_action",
        "error_status",
        "mfa_authenticated",
        "data_source",
        "attack_type",
        "scenario_id",
        "is_threat",
    ]
    df = df[column_order]

    # Save full dataset
    full_csv = os.path.join(OUTPUT_DIR, "cloudtrail_dataset.csv")
    df.to_csv(full_csv, index=False)
    print(f"\n[+] Full dataset saved: {full_csv} (Total: {len(df)} records)")
    print(f"  * Benign (0): {sum(df['is_threat'] == 0):,} ({sum(df['is_threat'] == 0)/len(df):.2%})")
    print(f"  * Threat (1): {sum(df['is_threat'] == 1):,} ({sum(df['is_threat'] == 1)/len(df):.2%})")

    # Train / Test Stratified Split (80/20)
    from sklearn.model_selection import train_test_split
    train_df, test_df = train_test_split(df, test_size=0.20, random_state=SEED, stratify=df["is_threat"])

    train_csv = os.path.join(OUTPUT_DIR, "train.csv")
    test_csv = os.path.join(OUTPUT_DIR, "test.csv")
    train_df.to_csv(train_csv, index=False)
    test_df.to_csv(test_csv, index=False)

    print(f"[+] Train split: {train_csv} ({len(train_df)} rows, Threat rate: {train_df['is_threat'].mean():.2%})")
    print(f"[+] Test split:  {test_csv} ({len(test_df)} rows, Threat rate: {test_df['is_threat'].mean():.2%})")

    # Save Raw CloudTrail Format Sample JSON
    raw_sample_path = os.path.join(OUTPUT_DIR, "sample_raw_events.json")
    sample_records = []
    for _, row in df.head(60).iterrows():
        rec = {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": row["identity_type"],
                "arn": row["identity_arn"],
                "userName": row["user_name"],
                "sessionContext": {
                    "attributes": {
                        "mfaAuthenticated": "true" if row["mfa_authenticated"] == 1 else "false"
                    }
                },
            },
            "eventTime": row["event_time"],
            "eventSource": row["event_source"],
            "eventName": row["event_name"],
            "awsRegion": row["aws_region"],
            "sourceIPAddress": row["source_ip"],
            "userAgent": row["user_agent"],
            "errorCode": "AccessDenied" if row["error_status"] == 1 else None,
            "errorMessage": "User is not authorized to perform action" if row["error_status"] == 1 else None,
            "requestParameters": {
                "userName": "target_admin_user" if row["target_user_is_different"] == 1 else row["user_name"]
            },
            "_ground_truth": int(row["is_threat"]),
            "_metadata": {
                "data_source": row["data_source"],
                "attack_type": row["attack_type"],
                "scenario_id": row["scenario_id"],
            },
        }
        sample_records.append(rec)

    with open(raw_sample_path, "w") as f:
        json.dump({"Records": sample_records}, f, indent=2)
    print(f"[+] Raw format samples saved: {raw_sample_path}")

    return df

if __name__ == "__main__":
    build_dataset()
