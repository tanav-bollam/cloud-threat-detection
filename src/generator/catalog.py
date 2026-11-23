"""API catalog: eventName -> (eventSource, readOnly, category, request/response builders).

Builders take (rng, ctx) where ctx is a dict with account, region and org naming helpers. Request
parameter shapes follow the AWS API reference so that rules can match real field paths."""
from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Callable, Optional

Builder = Optional[Callable[[random.Random, dict], dict]]


def hexid(rng: random.Random, n: int) -> str:
    return "".join(rng.choices("0123456789abcdef", k=n))


def upper_id(rng: random.Random, n: int) -> str:
    return "".join(rng.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", k=n))


@dataclass(frozen=True)
class Api:
    source: str
    read_only: bool
    category: str = "Management"  # or "Data"
    req: Builder = None
    resp: Builder = None
    err_code: str = "AccessDenied"  # errorCode used when the call is denied


BUCKETS = ["acme-prod-data", "acme-prod-logs", "acme-backups", "acme-analytics-lake", "acme-web-assets",
           "acme-ci-artifacts", "acme-dev-sandbox", "acme-ml-models", "acme-customer-exports", "acme-tf-state"]
TABLES = ["orders", "customers", "sessions", "events"]
INSTANCE_TYPES = ["t3.micro", "t3.small", "t3.medium", "m5.large", "c5.xlarge"]
LAMBDAS = ["order-processor", "etl-nightly", "thumbnailer", "webhook-relay", "report-builder", "auth-hook"]


def _bucket(rng, ctx):
    return rng.choice(BUCKETS)


def _key(rng, ctx):
    return f"{rng.choice(['data','exports','reports','logs','raw'])}/{rng.randint(2023,2025)}/{hexid(rng,8)}.{rng.choice(['csv','json','parquet','gz'])}"


def _s3_get(rng, ctx):
    b = ctx.get("bucket") or _bucket(rng, ctx)
    return {"bucketName": b, "Host": f"{b}.s3.amazonaws.com", "key": ctx.get("key") or _key(rng, ctx)}


def _s3_list(rng, ctx):
    b = ctx.get("bucket") or _bucket(rng, ctx)
    return {"bucketName": b, "Host": f"{b}.s3.amazonaws.com", "list-type": "2", "prefix": rng.choice(["data/", "logs/", "exports/", ""])}


def _s3_bucket_only(rng, ctx):
    b = ctx.get("bucket") or _bucket(rng, ctx)
    return {"bucketName": b, "Host": f"{b}.s3.amazonaws.com"}


def _iid(rng):
    return f"i-0{hexid(rng, 16)}"


def _run_instances(rng, ctx):
    itype = ctx.get("instance_type") or rng.choice(INSTANCE_TYPES)
    n = ctx.get("count", 1)
    return {"instancesSet": {"items": [{"imageId": f"ami-0{hexid(rng,16)}", "minCount": n, "maxCount": n}]},
            "instanceType": itype, "keyName": ctx.get("key_name", "dev-key"),
            "blockDeviceMapping": {}, "monitoring": {"enabled": False}}


def _run_instances_resp(rng, ctx):
    n = ctx.get("count", 1)
    return {"requestId": hexid(rng, 8), "reservationId": f"r-0{hexid(rng,16)}", "ownerId": ctx["account"],
            "instancesSet": {"items": [{"instanceId": _iid(rng), "instanceType": ctx.get("instance_type", "t3.micro")} for _ in range(n)]}}


def _instance_ids(rng, ctx):
    return {"instancesSet": {"items": [{"instanceId": _iid(rng)}]}}


def _user(rng, ctx):
    return {"userName": ctx.get("target_user") or rng.choice(["alice", "bob", "carol", "dave"])}


def _user_policy(rng, ctx):
    return {"userName": ctx.get("target_user", "svc-backup"),
            "policyArn": ctx.get("policy_arn", "arn:aws:iam::aws:policy/ReadOnlyAccess")}


def _put_user_policy(rng, ctx):
    return {"userName": ctx.get("target_user", "svc-backup"), "policyName": ctx.get("policy_name", "inline-policy"),
            "policyDocument": ctx.get("policy_doc", '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}')}


def _role_policy(rng, ctx):
    return {"roleName": ctx.get("role_name", "app-role"), "policyArn": ctx.get("policy_arn", "arn:aws:iam::aws:policy/ReadOnlyAccess")}


def _update_assume(rng, ctx):
    return {"roleName": ctx.get("role_name", "app-role"), "policyDocument": ctx.get(
        "trust_doc", '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}')}


def _create_access_key_resp(rng, ctx):
    return {"accessKey": {"userName": ctx.get("target_user", "alice"), "accessKeyId": "AKIA" + upper_id(rng, 16), "status": "Active", "createDate": "Jan 1, 2025 1:00:00 AM"}}


def _create_function(rng, ctx):
    return {"functionName": ctx.get("function_name") or f"{rng.choice(LAMBDAS)}-{hexid(rng,4)}", "runtime": "python3.12",
            "role": ctx.get("role_arn", f"arn:aws:iam::{ctx['account']}:role/lambda-exec"), "handler": "index.handler",
            "code": {"zipFile": "HIDDEN_DUE_TO_SECURITY_REASONS"}}


def _fn(rng, ctx):
    return {"functionName": ctx.get("function_name") or rng.choice(LAMBDAS)}


def _trail(rng, ctx):
    return {"name": ctx.get("trail_name", "org-trail")}


def _update_trail(rng, ctx):
    return {"name": ctx.get("trail_name", "org-trail"), "isMultiRegionTrail": False, "enableLogFileValidation": False}


def _event_selectors(rng, ctx):
    return {"trailName": ctx.get("trail_name", "org-trail"), "eventSelectors": [{"readWriteType": "WriteOnly", "includeManagementEvents": False, "dataResources": []}]}


def _detector(rng, ctx):
    return {"detectorId": ctx.get("detector_id", hexid(rng, 32))}


def _stable_id(prefix: str, *parts: str) -> str:
    import hashlib
    return prefix + "0" + hashlib.sha1("|".join(parts).encode()).hexdigest()[:16]


def flow_log_id_for(account: str, region: str) -> str:
    """The (single) VPC flow log the organisation runs in a region; shared by the generator (DeleteFlowLogs) and the flow-log generator."""
    return _stable_id("fl-", account, region)


def vpc_id_for(account: str, region: str) -> str:
    return _stable_id("vpc-", account, region)


def _flowlogs(rng, ctx):
    fid = ctx.get("flow_log_id") or f"fl-0{hexid(rng,16)}"
    return {"DeleteFlowLogsRequest": {"FlowLogId": {"content": fid, "tag": 1}}}


def _modify_snapshot(rng, ctx):
    return {"snapshotId": f"snap-0{hexid(rng,16)}", "attributeType": "CREATE_VOLUME_PERMISSION",
            "createVolumePermission": {"add": {"items": [{"userId": ctx.get("external_account", "999999999999")}]}}}


def _put_bucket_policy(rng, ctx):
    b = ctx.get("bucket") or _bucket(rng, ctx)
    return {"bucketName": b, "Host": f"{b}.s3.amazonaws.com", "policy": ctx.get(
        "policy", {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ctx['account']}:role/app"}, "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{b}/*"}]})}


def _put_bucket_acl(rng, ctx):
    b = ctx.get("bucket") or _bucket(rng, ctx)
    return {"bucketName": b, "Host": f"{b}.s3.amazonaws.com", "acl": ctx.get("acl", ["private"])}


def _assume_role(rng, ctx):
    return {"roleArn": ctx.get("role_arn", f"arn:aws:iam::{ctx['account']}:role/{rng.choice(['dev-role','readonly','deploy'])}"),
            "roleSessionName": ctx.get("session_name", f"sess-{hexid(rng,6)}"), "durationSeconds": 3600}


def _assume_resp(rng, ctx):
    return {"credentials": {"accessKeyId": "ASIA" + upper_id(rng, 16), "expiration": "Jan 1, 2025 2:00:00 PM", "sessionToken": "HIDDEN_DUE_TO_SECURITY_REASONS"}}


def _athena_start(rng, ctx):
    return {"queryString": rng.choice(["SELECT * FROM events LIMIT 1000", "SELECT count(*) FROM orders", "SELECT region, sum(total) FROM orders GROUP BY 1"]),
            "workGroup": "primary"}


def _qid(rng, ctx):
    return {"queryExecutionId": f"{hexid(rng,8)}-{hexid(rng,4)}-{hexid(rng,4)}-{hexid(rng,4)}-{hexid(rng,12)}"}


def _logs(rng, ctx):
    return {"logGroupName": f"/aws/lambda/{rng.choice(LAMBDAS)}"}


def _secret(rng, ctx):
    return {"secretId": rng.choice(["prod/db/password", "prod/api/key", "ci/registry-token"])}


def _param(rng, ctx):
    return {"name": rng.choice(["/app/config/db_host", "/app/config/feature_flags", "/ci/version"]), "withDecryption": True}


def _stack(rng, ctx):
    return {"stackName": rng.choice(["web-stack", "api-stack", "data-stack"])}


def _tags(rng, ctx):
    return {"resourcesSet": {"items": [{"resourceId": _iid(rng)}]}, "tagSet": {"items": [{"key": "owner", "value": "team"}]}}


def _sg_ingress(rng, ctx):
    return {"groupId": f"sg-0{hexid(rng,16)}", "ipPermissions": {"items": [{"ipProtocol": "tcp", "fromPort": 22, "toPort": 22, "ipRanges": {"items": [{"cidrIp": ctx.get("cidr", "10.0.0.0/8")}]}}]}}


def _spot(rng, ctx):
    return {"spotPrice": "5.0", "instanceCount": ctx.get("count", 1), "launchSpecification": {"instanceType": ctx.get("instance_type", "p3.16xlarge"), "imageId": f"ami-0{hexid(rng,16)}"}}


def _create_user(rng, ctx):
    return {"userName": ctx.get("target_user", "new.user")}


def _login_profile(rng, ctx):
    return {"userName": ctx.get("target_user", "alice"), "passwordResetRequired": False}


def _create_snapshot(rng, ctx):
    return {"volumeId": f"vol-0{hexid(rng,16)}", "description": "backup"}


def _decrypt(rng, ctx):
    return {"encryptionContext": {"SecretARN": f"arn:aws:secretsmanager:{ctx['region']}:{ctx['account']}:secret:prod/db/password"}, "encryptionAlgorithm": "SYMMETRIC_DEFAULT"}


def _ecr_token(rng, ctx):
    return {"registryIds": [ctx["account"]]}


_S3 = "s3.amazonaws.com"
_EC2 = "ec2.amazonaws.com"
_IAM = "iam.amazonaws.com"

API: dict[str, Api] = {
    # ---- STS / sign-in
    "GetCallerIdentity": Api("sts.amazonaws.com", True),
    "AssumeRole": Api("sts.amazonaws.com", True, req=_assume_role, resp=_assume_resp),
    # ---- EC2
    "DescribeInstances": Api(_EC2, True, err_code="Client.UnauthorizedOperation"),
    "DescribeSecurityGroups": Api(_EC2, True, err_code="Client.UnauthorizedOperation"),
    "DescribeVolumes": Api(_EC2, True, err_code="Client.UnauthorizedOperation"),
    "DescribeSnapshots": Api(_EC2, True, err_code="Client.UnauthorizedOperation"),
    "DescribeVpcs": Api(_EC2, True, err_code="Client.UnauthorizedOperation"),
    "DescribeImages": Api(_EC2, True, err_code="Client.UnauthorizedOperation"),
    "DescribeRegions": Api(_EC2, True, err_code="Client.UnauthorizedOperation"),
    "RunInstances": Api(_EC2, False, req=_run_instances, resp=_run_instances_resp, err_code="Client.UnauthorizedOperation"),
    "StartInstances": Api(_EC2, False, req=_instance_ids, err_code="Client.UnauthorizedOperation"),
    "StopInstances": Api(_EC2, False, req=_instance_ids, err_code="Client.UnauthorizedOperation"),
    "TerminateInstances": Api(_EC2, False, req=_instance_ids, err_code="Client.UnauthorizedOperation"),
    "CreateTags": Api(_EC2, False, req=_tags, err_code="Client.UnauthorizedOperation"),
    "AuthorizeSecurityGroupIngress": Api(_EC2, False, req=_sg_ingress, err_code="Client.UnauthorizedOperation"),
    "ModifySnapshotAttribute": Api(_EC2, False, req=_modify_snapshot, err_code="Client.UnauthorizedOperation"),
    "CreateSnapshot": Api(_EC2, False, req=_create_snapshot, err_code="Client.UnauthorizedOperation"),
    "RequestSpotInstances": Api(_EC2, False, req=_spot, err_code="Client.UnauthorizedOperation"),
    "DeleteFlowLogs": Api(_EC2, False, req=_flowlogs, err_code="Client.UnauthorizedOperation"),
    # ---- S3 (bucket-level are management events; object-level are data events)
    "ListBuckets": Api(_S3, True, req=lambda r, c: {"Host": "s3.amazonaws.com"}),
    "GetBucketLocation": Api(_S3, True, req=_s3_bucket_only),
    "GetBucketAcl": Api(_S3, True, req=_s3_bucket_only),
    "GetBucketPolicy": Api(_S3, True, req=_s3_bucket_only, err_code="NoSuchBucketPolicy"),
    "PutBucketPolicy": Api(_S3, False, req=_put_bucket_policy),
    "PutBucketAcl": Api(_S3, False, req=_put_bucket_acl),
    "DeleteBucket": Api(_S3, False, req=_s3_bucket_only),
    "GetObject": Api(_S3, True, "Data", req=_s3_get),
    "PutObject": Api(_S3, False, "Data", req=_s3_get),
    "ListObjects": Api(_S3, True, "Data", req=_s3_list),
    # ---- IAM
    "ListUsers": Api(_IAM, True), "ListRoles": Api(_IAM, True), "ListPolicies": Api(_IAM, True),
    "ListGroups": Api(_IAM, True), "GetAccountSummary": Api(_IAM, True),
    "GetAccountAuthorizationDetails": Api(_IAM, True),
    "GetUser": Api(_IAM, True, req=_user), "ListAccessKeys": Api(_IAM, True, req=_user),
    "ListAttachedUserPolicies": Api(_IAM, True, req=_user),
    "CreateUser": Api(_IAM, False, req=_create_user),
    "CreateAccessKey": Api(_IAM, False, req=_user, resp=_create_access_key_resp),
    "DeleteAccessKey": Api(_IAM, False, req=lambda r, c: {"userName": c.get("target_user", "alice"), "accessKeyId": "AKIA" + upper_id(r, 16)}),
    "AttachUserPolicy": Api(_IAM, False, req=_user_policy),
    "PutUserPolicy": Api(_IAM, False, req=_put_user_policy),
    "AttachRolePolicy": Api(_IAM, False, req=_role_policy),
    "PutRolePolicy": Api(_IAM, False, req=lambda r, c: {"roleName": c.get("role_name", "app-role"), "policyName": "inline", "policyDocument": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"logs:*","Resource":"*"}]}'}),
    "CreateLoginProfile": Api(_IAM, False, req=_login_profile),
    "UpdateAssumeRolePolicy": Api(_IAM, False, req=_update_assume),
    "CreateRole": Api(_IAM, False, req=lambda r, c: {"roleName": c.get("role_name", "new-role"), "assumeRolePolicyDocument": c.get("trust_doc", "{}")}),
    # ---- Lambda
    "ListFunctions20150331": Api("lambda.amazonaws.com", True),
    "GetFunction20150331v2": Api("lambda.amazonaws.com", True, req=_fn),
    "CreateFunction20150331": Api("lambda.amazonaws.com", False, req=_create_function),
    "UpdateFunctionCode20150331v2": Api("lambda.amazonaws.com", False, req=_fn),
    # ---- CloudTrail / GuardDuty / logs
    "DescribeTrails": Api("cloudtrail.amazonaws.com", True),
    "GetTrailStatus": Api("cloudtrail.amazonaws.com", True, req=_trail),
    "LookupEvents": Api("cloudtrail.amazonaws.com", True),
    "StopLogging": Api("cloudtrail.amazonaws.com", False, req=_trail),
    "DeleteTrail": Api("cloudtrail.amazonaws.com", False, req=_trail),
    "UpdateTrail": Api("cloudtrail.amazonaws.com", False, req=_update_trail),
    "PutEventSelectors": Api("cloudtrail.amazonaws.com", False, req=_event_selectors),
    "ListDetectors": Api("guardduty.amazonaws.com", True),
    "DeleteDetector": Api("guardduty.amazonaws.com", False, req=_detector),
    "UpdateDetector": Api("guardduty.amazonaws.com", False, req=lambda r, c: {"detectorId": hexid(r, 32), "enable": False}),
    "DescribeLogGroups": Api("logs.amazonaws.com", True), "DescribeLogStreams": Api("logs.amazonaws.com", True, req=_logs),
    "GetLogEvents": Api("logs.amazonaws.com", True, req=_logs), "FilterLogEvents": Api("logs.amazonaws.com", True, req=_logs),
    # ---- Data / analytics
    "StartQueryExecution": Api("athena.amazonaws.com", False, req=_athena_start, resp=_qid),
    "GetQueryExecution": Api("athena.amazonaws.com", True, req=_qid),
    "GetQueryResults": Api("athena.amazonaws.com", True, req=_qid),
    "GetTable": Api("glue.amazonaws.com", True, req=lambda r, c: {"databaseName": "analytics", "name": r.choice(TABLES)}),
    "GetDatabases": Api("glue.amazonaws.com", True),
    "ListTables": Api("dynamodb.amazonaws.com", True), "DescribeTable": Api("dynamodb.amazonaws.com", True, req=lambda r, c: {"tableName": r.choice(TABLES)}),
    "ListKeys": Api("kms.amazonaws.com", True), "Decrypt": Api("kms.amazonaws.com", True, req=_decrypt),
    "ListSecrets": Api("secretsmanager.amazonaws.com", True),
    "GetSecretValue": Api("secretsmanager.amazonaws.com", True, req=_secret),
    "GetParameter": Api("ssm.amazonaws.com", True, req=_param),
    "DescribeStacks": Api("cloudformation.amazonaws.com", True, req=_stack),
    "UpdateStack": Api("cloudformation.amazonaws.com", False, req=_stack),
    "GetAuthorizationToken": Api("ecr.amazonaws.com", True, req=_ecr_token),
    "PutImage": Api("ecr.amazonaws.com", False),
    "ListClusters": Api("ecs.amazonaws.com", True),
    "DescribeDBInstances": Api("rds.amazonaws.com", True),
    "ListQueues": Api("sqs.amazonaws.com", True), "ListTopics": Api("sns.amazonaws.com", True),
    "DescribeAlarms": Api("monitoring.amazonaws.com", True),
    "ListHostedZones": Api("route53.amazonaws.com", True),
    "ListDistributions": Api("cloudfront.amazonaws.com", True),
    # sign-in is special-cased in the builder (eventType AwsConsoleSignIn)
    "ConsoleLogin": Api("signin.amazonaws.com", False),
}

# Convenience sets used by generators and (later) detectors
RECON_APIS = [n for n, a in API.items() if a.read_only and a.category == "Management" and n.startswith(("List", "Describe", "Get"))
              and n not in ("GetSecretValue", "GetParameter", "GetAuthorizationToken", "GetLogEvents")]
