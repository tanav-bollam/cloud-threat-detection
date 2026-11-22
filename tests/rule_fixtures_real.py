"""Fixtures for rules added after real-data validation (Stratus Red Team samples). Request shapes are copied from the REAL records.
Imported at the end of tests/test_rules.py, which merges these into FIXTURES (every rule must have positive and negative fixtures)."""
import json

from src.generator.schema import validate_record
from tests.test_rules import ACCT, ALICE, FIXTURES, ROLE, TRUST_SVC, mk

OTHER = "999988887777"


def raw(name, source, params, who=ALICE, t=0, error=None, resp=None):
    rec = mk("GetCallerIdentity", t=t, who=who)
    rec["eventName"], rec["eventSource"], rec["requestParameters"], rec["responseElements"] = name, source, params, resp
    rec["readOnly"] = name.startswith(("Get", "List", "Describe"))
    if error:
        rec["errorCode"] = error
    validate_record(rec)
    return rec


SG_OPEN_REAL = raw("AuthorizeSecurityGroupIngress", "ec2.amazonaws.com", {"cidrIp": "208.236.235.254/0", "fromPort": 22, "groupId": "sg-003dc7f1f1c686164", "ipPermissions": {}, "ipProtocol": "tcp", "toPort": 22})
SG_OPEN_RULESET = raw("AuthorizeSecurityGroupIngress", "ec2.amazonaws.com", {"groupId": "sg-1", "ipPermissions": {}},
                      resp={"securityGroupRuleSet": {"items": [{"cidrIpv4": "0.0.0.0/0", "fromPort": 22}]}})
SG_OPEN_V6 = raw("AuthorizeSecurityGroupIngress", "ec2.amazonaws.com", {"ipPermissions": {"items": [{"ipv6Ranges": {"items": [{"cidrIpv6": "::/0"}]}}]}})
SG_PRIVATE = raw("AuthorizeSecurityGroupIngress", "ec2.amazonaws.com", {"cidrIp": "10.0.0.0/16", "fromPort": 22, "ipPermissions": {}})
CREATE_ROLE_EXT = raw("CreateRole", "iam.amazonaws.com", {"roleName": "x", "assumeRolePolicyDocument": json.dumps(
    {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::193672423079:root"}, "Action": "sts:AssumeRole"}]})})
CREATE_ROLE_SVC = raw("CreateRole", "iam.amazonaws.com", {"roleName": "x", "assumeRolePolicyDocument": TRUST_SVC})

# fixes for shapes the original fixtures did not know about (found by real data)
FIXTURES["R017"][0].extend([[SG_OPEN_REAL], [SG_OPEN_RULESET], [SG_OPEN_V6]])
FIXTURES["R017"][1].append([SG_PRIVATE])
FIXTURES["R009"][0].append([CREATE_ROLE_EXT])
FIXTURES["R009"][1].append([CREATE_ROLE_SVC])


def secrets(n, who=ALICE):
    return [raw("GetSecretValue", "secretsmanager.amazonaws.com", {"secretId": f"s{i}"}, t=i, who=who) for i in range(n)]


FIXTURES.update({
    "R025": ([[raw("ModifyImageAttribute", "ec2.amazonaws.com", {"attributeType": "launchPermission", "imageId": "ami-1", "launchPermission": {"add": {"items": [{"userId": OTHER}]}}})],
              [raw("ModifyImageAttribute", "ec2.amazonaws.com", {"launchPermission": {"add": {"items": [{"group": "all"}]}}})]],
             [[raw("ModifyImageAttribute", "ec2.amazonaws.com", {"launchPermission": {"add": {"items": [{"userId": ACCT}]}}})],
              [raw("ModifyImageAttribute", "ec2.amazonaws.com", {"description": {"value": "x"}})]]),
    "R026": ([[raw("ModifyDBSnapshotAttribute", "rds.amazonaws.com", {"attributeName": "restore", "dBSnapshotIdentifier": "s", "valuesToAdd": [OTHER]})],
              [raw("ModifyDBClusterSnapshotAttribute", "rds.amazonaws.com", {"attributeName": "restore", "valuesToAdd": ["all"]})]],
             [[raw("ModifyDBSnapshotAttribute", "rds.amazonaws.com", {"attributeName": "restore", "valuesToAdd": [ACCT]})],
              [raw("ModifyDBSnapshotAttribute", "rds.amazonaws.com", {"attributeName": "other", "valuesToAdd": [OTHER]})]]),
    "R027": ([[raw("AddPermission20150331v2", "lambda.amazonaws.com", {"action": "lambda:InvokeFunction", "functionName": "f", "principal": "*", "statementId": "backdoor"})]],
             [[raw("AddPermission20150331v2", "lambda.amazonaws.com", {"action": "lambda:InvokeFunction", "functionName": "f", "principal": "apigateway.amazonaws.com"})],
              [raw("AddPermission20150331v2", "lambda.amazonaws.com", {"principal": "*", "sourceArn": "arn:aws:s3:::my-bucket"})]]),
    "R028": ([[raw("GetPasswordData", "ec2.amazonaws.com", {"instanceId": "i-1"}, error="Client.UnauthorizedOperation")]], [[raw("GetConsoleOutput", "ec2.amazonaws.com", {"instanceId": "i-1"})]]),
    "R029": ([[raw("BatchGetSecretValue", "secretsmanager.amazonaws.com", {"filters": [{"key": "tag-key", "values": ["x"]}]})]],
             [[raw("GetSecretValue", "secretsmanager.amazonaws.com", {"secretId": "s"})]]),
    "R030": ([secrets(10)], [secrets(9), secrets(60, who=ROLE)]),
    "R031": ([[raw("GetParameters", "ssm.amazonaws.com", {"names": [f"/p/{i}" for i in range(12)]})]],
             [[raw("GetParameters", "ssm.amazonaws.com", {"names": ["/p/1", "/p/2"]})], [raw("GetParameter", "ssm.amazonaws.com", {"name": "/p/1"})]]),
    "R032": ([[raw("SendCommand", "ssm.amazonaws.com", {"documentName": "AWS-RunShellScript", "instanceIds": ["i-1"]})], [raw("StartSession", "ssm.amazonaws.com", {"target": "i-1"})]],
             [[raw("DescribeInstanceInformation", "ssm.amazonaws.com", {})], [raw("GetCommandInvocation", "ssm.amazonaws.com", {"commandId": "c"})]]),
    "R033": ([[raw("SendSSHPublicKey", "ec2-instance-connect.amazonaws.com", {"instanceId": "i-1", "instanceOSUser": "ec2-user"})],
              [raw("EnableSerialConsoleAccess", "ec2.amazonaws.com", {"EnableSerialConsoleAccessRequest": ""})]],
             [[raw("DescribeInstances", "ec2.amazonaws.com", {})]]),
    "R034": ([[raw("ModifyInstanceAttribute", "ec2.amazonaws.com", {"instanceId": "i-1", "userData": "<sensitiveDataRemoved>"})]],
             [[raw("ModifyInstanceAttribute", "ec2.amazonaws.com", {"instanceId": "i-1", "instanceType": {"value": "t3.micro"}})]]),
    "R035": ([[raw("DescribeInstanceAttribute", "ec2.amazonaws.com", {"attribute": "userData", "instanceId": "i-1"}, error="Client.UnauthorizedOperation")]],
             [[raw("DescribeInstanceAttribute", "ec2.amazonaws.com", {"attribute": "instanceType", "instanceId": "i-1"})]]),
    "R036": ([[raw("LeaveOrganization", "organizations.amazonaws.com", None, who=ROLE, error="AccessDenied")]], [[raw("ListAccounts", "organizations.amazonaws.com", None)]]),
    "R037": ([[raw("DeleteResolverQueryLogConfig", "route53resolver.amazonaws.com", {"resolverQueryLogConfigId": "rqlc-1"})]],
             [[raw("ListResolverQueryLogConfigs", "route53resolver.amazonaws.com", {})]]),
    "R038": ([[raw("GetFederationToken", "sts.amazonaws.com", {"name": "stratus_red_team", "policy": "{}"})]], [[raw("GetCallerIdentity", "sts.amazonaws.com", None)]]),
    "R039": ([[raw("CreateTrustAnchor", "rolesanywhere.amazonaws.com", {"name": "ta", "enabled": True})], [raw("CreateProfile", "rolesanywhere.amazonaws.com", {"name": "p"})]],
             [[raw("CreateProfile", "iam.amazonaws.com", {"name": "p"})], [raw("ListTrustAnchors", "rolesanywhere.amazonaws.com", {})]]),
    "R040": ([[raw("UpdateLoginProfile", "iam.amazonaws.com", {"userName": "bob"})]], [[raw("UpdateLoginProfile", "iam.amazonaws.com", {"userName": "alice"})]]),
    "R041": ([[raw("InvokeModel", "bedrock.amazonaws.com", {"modelId": "anthropic.claude-3-sonnet"})]], [[raw("ListFoundationModels", "bedrock.amazonaws.com", {})]]),
})
