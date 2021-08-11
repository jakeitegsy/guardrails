import unittest
import guardrails


class TestGuardrailGenerator(unittest.TestCase):

    maxDiff = None

    def test_disallow_changes_to_encryption_configuration_for_s3_buckets(self):
        self.assertEqual(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "GRCTAUDITBUCKETENCRYPTIONCHANGESPROHIBITED",
                        "Effect": "Deny",
                        "Action": [
                            "s3:PutEncryptionConfiguration"
                        ],
                        "Resource": ["arn:aws:s3:::aws-controltower*"],
                        "Condition": {
                            "ArnNotLike": {
                                "aws:PrincipalARN": "arn:aws:iam::*:role/AWSControlTowerExecution"
                            }
                        }
                    }
                ]
            },
            guardrails.disallow_changes_to_encryption_configuration_for_s3_buckets()
        )

    def test_disallow_changes_to_logging_configuration_for_s3_buckets(self):
        self.assertEqual(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "GRCTAUDITBUCKETLOGGINGCONFIGURATIONCHANGESPROHIBITED",
                        "Effect": "Deny",
                        "Action": [
                            "s3:PutBucketLogging"
                        ],
                        "Resource": ["arn:aws:s3:::aws-controltower*"],
                        "Condition": {
                            "ArnNotLike": {
                                "aws:PrincipalARN": "arn:aws:iam::*:role/AWSControlTowerExecution"
                            }
                        }
                    }
                ]
            },
            guardrails.disallow_changes_to_logging_configuration_for_s3_buckets()
        )

    def test_disallow_changes_to_s3_configuration(self):
        self.assertEqual(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "GRRESTRICTS3CROSSREGIONREPLICATION",
                        "Effect": "Deny",
                        "Action": [
                            "s3:PutReplicationConfiguration"
                        ],
                        "Resource": [
                            "*"
                        ]
                    }
                ]
            }, guardrails.disallow_changes_to_s3_configuration())

    def test_disallow_changes_to_bucket_policy_for_s3_buckets(self):
        self.assertEqual(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "GRCTAUDITBUCKETPOLICYCHANGESPROHIBITED",
                        "Effect": "Deny",
                        "Action": [
                            "s3:PutBucketPolicy",
                            "s3:DeleteBucketPolicy"
                        ],
                        "Resource": ["arn:aws:s3:::aws-controltower*"],
                        "Condition": {
                            "ArnNotLike": {
                                "aws:PrincipalARN": "arn:aws:iam::*:role/AWSControlTowerExecution"
                            }
                        }
                    }
                ]
            },
            guardrails.disallow_changes_to_bucket_policy_for_s3_buckets()
        )

    def test_disallow_lifecycle_configuration_changes_to_s3_buckets(self):
        self.assertEqual(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "GRCTAUDITBUCKETLIFECYCLECONFIGURATIONCHANGESPROHIBITED",
                        "Effect": "Deny",
                        "Action": [
                            "s3:PutLifecycleConfiguration"
                        ],
                        "Resource": ["arn:aws:s3:::aws-controltower*"],
                        "Condition": {
                            "ArnNotLike": {
                                "aws:PrincipalARN": "arn:aws:iam::*:role/AWSControlTowerExecution"
                            }
                        }
                    }
                ]
            },
            guardrails.disallow_lifecycle_configuration_changes_to_s3_buckets()

        )

    def test_disallow_S3_delete_without_mfa(self):
        self.assertEqual(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "GRRESTRICTS3DELETEWITHOUTMFA",
                        "Effect": "Deny",
                        "Action": [
                            "s3:DeleteObject",
                            "s3:DeleteBucket"
                        ],
                        "Resource": [
                            "*"
                        ],
                        "Condition": {
                            "BoolIfExists": {
                                "aws:MultiFactorAuthPresent": [
                                    "false"
                                ]
                            }
                        }
                    }
                ]
            }, guardrails.disallow_S3_delete_without_mfa())

    def test_mfa_enabled_for_iam_user(self):
        self.assertEqual(
            {
                "AWSTemplateFormatVersion": "2010-09-09",
                "Description": "Configure AWS Config rules to check whether the IAM users have MFA enabled",
                "Resources": {
                    "IAMUserMFA": {
                        "Type": "AWS::Config::ConfigRule",
                        "Properties": {
                                "ConfigRuleName": 'IAMUserMFA',
                                "Description": "Checks whether the AWS Identity and Access Management users have multi-factor authentication (MFA) enabled. The rule is COMPLIANT if MFA is enabled.",
                                "Source": {
                                    "Owner": "AWS",
                                    "SourceIdentifier": "IAM_USER_MFA_ENABLED"
                                },
                            "MaximumExecutionFrequency": 'One_Hour'
                        }
                    }
                }
            }, guardrails.check_mfa_enabled_for_iam_user())

    def test_mfa_enabled_for_iam_user_through_console(self):
        self.assertEqual({
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": "Configure AWS Config rules to check whether MFA is enabled for all AWS IAM users that use a console password.",
            "Resources": {
                "IAMUserConsoleMFA": {
                    "Type": "AWS::Config::ConfigRule",
                    "Properties": {
                        "ConfigRuleName": 'IAMUserConsoleMFA',
                        "Description": "Checks whether AWS Multi-Factor Authentication (MFA) is enabled for all AWS Identity and Access Management (IAM) users that use a console password. The rule is COMPLIANT if MFA is enabled.",
                        "Source": {
                            "Owner": "AWS",
                            "SourceIdentifier": "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS"
                        },
                        "MaximumExecutionFrequency": 'One_Hour'
                    }
                }
            }
        }, guardrails.check_mfa_enabled_for_iam_user_through_console())

    def test_disallow_changes_to_cloudwatch_logs(self):
        self.assertEqual(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "GRLOGGROUPPOLICY",
                        "Effect": "Deny",
                        "Action": [
                            "logs:DeleteLogGroup",
                            "logs:PutRetentionPolicy"
                        ],
                        "Resource": [
                            "arn:aws:logs:*:*:log-group:*aws-controltower*"
                        ],
                        "Condition": {
                            "StringNotLike": {
                                "aws:PrincipalARN": "arn:aws:iam::*:role/AWSControlTowerExecution"
                            }
                        }
                    }
                ]
            },
            guardrails.disallow_changes_to_cloudwatch_logs(),
        )

    def test_disallow_cloudwatch_events_changes(self):
        self.assertEqual(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "GRCLOUDWATCHEVENTPOLICY",
                        "Effect": "Deny",
                        "Action": [
                            "events:PutRule",
                            "events:PutTargets",
                            "events:RemoveTargets",
                            "events:DisableRule",
                            "events:DeleteRule"
                        ],
                        "Resource": [
                            "arn:aws:events:*:*:rule/aws-controltower-*"
                        ],
                        "Condition": {
                            "ArnNotLike": {
                                "aws:PrincipalARN": "arn:aws:iam::*:role/AWSControlTowerExecution"
                            }
                        }
                    }
                ]
            },
            guardrails.disallow_cloudwatch_events_changes()
        )

    def test_disallow_deletion_of_config_aggregation_authorizations(self):
        self.assertEqual(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "GRCONFIGAGGREGATIONAUTHORIZATIONPOLICY",
                        "Effect": "Deny",
                        "Action": [
                            "config:DeleteAggregationAuthorization"
                        ],
                        "Resource": [
                            "arn:aws:config:*:*:aggregation-authorization*"
                        ],
                        "Condition": {
                            "ArnNotLike": {
                                "aws:PrincipalARN": "arn:aws:iam::*:role/AWSControlTowerExecution"
                            },
                            "StringLike": {
                                "aws:ResourceTag/aws-control-tower": "managed-by-control-tower"
                            }
                        }
                    }
                ]
            },
            guardrails.disallow_deletion_of_config_aggregation_authorizations()
        )

    def test_disallow_deletion_of_log_archive(self):
        self.assertEqual(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "GRAUDITBUCKETDELETIONPROHIBITED",
                        "Effect": "Deny",
                        "Action": [
                            "s3:DeleteBucket"
                        ],
                        "Resource": [
                            "arn:aws:s3:::aws-controltower*"
                        ],
                        "Condition": {
                            "ArnNotLike": {
                                "aws:PrincipalARN": "arn:aws:iam::*:role/AWSControlTowerExecution"
                            }
                        }
                    }
                ]
            },
            guardrails.disallow_deletion_of_s3_log_archive()
        )

    def test_disallow_encryption_settings_changes_to_s3(self):
        self.assertEqual(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "GRAUDITBUCKETENCRYPTIONENABLED",
                        "Effect": "Deny",
                        "Action": [
                            "s3:PutEncryptionConfiguration"
                        ],
                        "Resource": ["*"],
                        "Condition": {
                            "ArnNotLike": {
                                "aws:PrincipalARN": "arn:aws:iam::*:role/AWSControlTowerExecution"
                            }
                        }
                    }
                ]
            }, guardrails.disallow_encryption_settings_changes_to_s3()
        )

    def test_disallow_changes_to_s3_logging(self):
        self.assertEqual({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "GRAUDITBUCKETLOGGINGENABLED",
                    "Effect": "Deny",
                    "Action": [
                        "s3:PutBucketLogging"
                    ],
                    "Resource": ["*"],
                    "Condition": {
                        "ArnNotLike": {
                            "aws:PrincipalARN": "arn:aws:iam::*:role/AWSControlTowerExecution"
                        }
                    }
                }
            ]
        }, guardrails.disallow_changes_to_s3_logging()
        )

    def test_disallow_changes_to_s3_bucket_policy(self):
        self.assertEqual(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "GRAUDITBUCKETPOLICYCHANGESPROHIBITED",
                        "Effect": "Deny",
                        "Action": [
                            "s3:PutBucketPolicy"
                        ],
                        "Resource": ["*"],
                        "Condition": {
                            "ArnNotLike": {
                                "aws:PrincipalARN": "arn:aws:iam::*:role/AWSControlTowerExecution"
                            }
                        }
                    }
                ]
            }, guardrails.disallow_changes_to_s3_bucket_policy()
        )

    def test_disallow_changes_to_s3_lifecycle_configuration(self):
        self.assertEqual(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "GRAUDITBUCKETRETENTIONPOLICY",
                        "Effect": "Deny",
                        "Action": [
                            "s3:PutLifecycleConfiguration"
                        ],
                        "Resource": ["*"],
                        "Condition": {
                            "ArnNotLike": {
                                "aws:PrincipalARN": "arn:aws:iam::*:role/AWSControlTowerExecution"
                            }
                        }
                    }
                ]
            }, guardrails.disallow_changes_to_s3_lifecycle_configuration())

    def test_config_rule_for_s3_public_read_access(self):
        self.assertEqual(
            {
                "AWSTemplateFormatVersion": "2010-09-09",
                "Description": "Configure AWS Config rules to check that your S3 buckets do not allow public access",
                "Resources": {
                    "S3PublicRead": {
                        "Type": "AWS::Config::ConfigRule",
                        "Properties": {
                            "ConfigRuleName": "S3PublicRead",
                            "Description": "Checks that your S3 buckets do not allow public read access. If an S3 bucket policy or bucket ACL allows public read access, the bucket is noncompliant.",
                            "Source": {
                                "Owner": "AWS",
                                "SourceIdentifier": "S3_BUCKET_PUBLIC_READ_PROHIBITED"
                            },
                            "Scope": {
                                "ComplianceResourceTypes": [
                                    "AWS::S3::Bucket"
                                ]
                            }
                        }
                    }
                }
            },
            guardrails.config_rule_for_s3_public_read_access()
        )

    def test_config_rule_for_s3_public_write_access(self):
        self.assertEqual(
            {
                "AWSTemplateFormatVersion": "2010-09-09",
                "Description": "Configure AWS Config rules to check that your S3 buckets do not allow public access",
                "Resources": {
                    "S3PublicWrite": {
                        "Type": "AWS::Config::ConfigRule",
                        "Properties": {
                            "ConfigRuleName": "S3PublicWrite",
                            "Description": "Checks that your S3 buckets do not allow public write access. If an S3 bucket policy or bucket ACL allows public write access, the bucket is noncompliant.",
                            "Source": {
                                "Owner": "AWS",
                                "SourceIdentifier": "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
                            },
                            "Scope": {
                                "ComplianceResourceTypes": [
                                    "AWS::S3::Bucket"
                                ]
                            }
                        }
                    }
                }
            },
            guardrails.config_rule_for_s3_public_write_access()
        )

    def test_versioning_enabled(self):
        self.assertEqual(
            {
                "AWSTemplateFormatVersion": "2010-09-09",
                "Description": "Configure AWS Config rules to check whether versioning is enabled for your S3 buckets.",
                "Resources": {
                    "S3Versioning": {
                        "Type": "AWS::Config::ConfigRule",
                        "Properties": {
                            "ConfigRuleName": 'S3Versioning',
                            "Description": "Checks whether versioning is enabled for your S3 buckets.",
                            "Source": {
                                "Owner": "AWS",
                                "SourceIdentifier": "S3_BUCKET_VERSIONING_ENABLED"
                            },
                            "Scope": {
                                "ComplianceResourceTypes": [
                                    "AWS::S3::Bucket"
                                ]
                            }
                        }
                    }
                }
            }, guardrails.versioning_enabled())

    def test_enable_cloudtrail(self):
        self.assertEqual(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "GRCLOUDTRAILENABLED",
                        "Effect": "Deny",
                        "Action": [
                            "cloudtrail:DeleteTrail",
                            "cloudtrail:PutEventSelectors",
                            "cloudtrail:StopLogging",
                            "cloudtrail:UpdateTrail"
                        ],
                        "Resource": ["arn:aws:cloudtrail:*:*:trail/aws-controltower-*"],
                        "Condition": {
                            "ArnNotLike": {
                                "aws:PrincipalARN": "arn:aws:iam::*:role/AWSControlTowerExecution"
                            }
                        }
                    }
                ]
            },
            guardrails.enable_cloudtrail()
        )

    def test_disallow_config_rule_tags_changes(self):
        self.assertEqual(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "GRCONFIGRULETAGSPOLICY",
                        "Effect": "Deny",
                        "Action": [
                            "config:TagResource",
                            "config:UntagResource"
                        ],
                        "Resource": ["*"],
                        "Condition": {
                            "ArnNotLike": {
                                "aws:PrincipalARN": "arn:aws:iam::*:role/AWSControlTowerExecution"
                            },
                            "ForAllValues:StringEquals": {
                                "aws:TagKeys": "aws-control-tower"
                            }
                        }
                    }
                ]
            },
            guardrails.disallow_config_rule_tag_changes()
        )

    def test_enable_config(self):
        self.assertEqual(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "GRCONFIGENABLED",
                        "Effect": "Deny",
                        "Action": [
                            "config:DeleteConfigurationRecorder",
                            "config:DeleteDeliveryChannel",
                            "config:DeleteRetentionConfiguration",
                            "config:PutConfigurationRecorder",
                            "config:PutDeliveryChannel",
                            "config:PutRetentionConfiguration",
                            "config:StopConfigurationRecorder"
                        ],
                        "Resource": ["*"],
                        "Condition": {
                            "ArnNotLike": {
                                "aws:PrincipalARN": "arn:aws:iam::*:role/AWSControlTowerExecution"
                            }
                        }
                    }
                ]
            },
            guardrails.enable_config()
        )

    def test_disallow_config_rule_changes(self):
        self.assertEqual(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "GRCONFIGRULEPOLICY",
                        "Effect": "Deny",
                        "Action": [
                            "config:PutConfigRule",
                            "config:DeleteConfigRule",
                            "config:DeleteEvaluationResults",
                            "config:DeleteConfigurationAggregator",
                            "config:PutConfigurationAggregator"
                        ],
                        "Resource": ["*"],
                        "Condition": {
                            "ArnNotLike": {
                                "aws:PrincipalARN": "arn:aws:iam::*:role/AWSControlTowerExecution"
                            },
                            "StringEquals": {
                                "aws:ResourceTag/aws-control-tower": "managed-by-control-tower"
                            }
                        }
                    }
                ]
            },
            guardrails.disallow_config_rule_changes()
        )

    def test_iam_role_policy(self):
        self.assertEqual(

            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "GRIAMROLEPOLICY",
                        "Effect": "Deny",
                        "Action": [
                            "iam:AttachRolePolicy",
                            "iam:CreateRole",
                            "iam:DeleteRole",
                            "iam:DeleteRolePermissionsBoundary",
                            "iam:DeleteRolePolicy",
                            "iam:DetachRolePolicy",
                            "iam:PutRolePermissionsBoundary",
                            "iam:PutRolePolicy",
                            "iam:UpdateAssumeRolePolicy",
                            "iam:UpdateRole",
                            "iam:UpdateRoleDescription"
                        ],
                        "Resource": [
                            "arn:aws:iam::*:role/aws-controltower-*",
                            "arn:aws:iam::*:role/*AWSControlTower*",
                            "arn:aws:iam::*:role/stacksets-exec-*"  # this line is new
                        ],
                        "Condition": {
                            "ArnNotLike": {
                                "aws:PrincipalArn": [
                                    "arn:aws:iam::*:role/AWSControlTowerExecution",
                                    "arn:aws:iam::*:role/stacksets-exec-*"  # this line is new
                                ]
                            }
                        }
                    }
                ]
            },
            guardrails.iam_role_policy()
        )

    def test_disallow_lambda_changes(self):
        self.assertEqual(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "GRLAMBDAFUNCTIONPOLICY",
                        "Effect": "Deny",
                        "Action": [
                            "lambda:AddPermission",
                            "lambda:CreateEventSourceMapping",
                            "lambda:CreateFunction",
                            "lambda:DeleteEventSourceMapping",
                            "lambda:DeleteFunction",
                            "lambda:DeleteFunctionConcurrency",
                            "lambda:PutFunctionConcurrency",
                            "lambda:RemovePermission",
                            "lambda:UpdateEventSourceMapping",
                            "lambda:UpdateFunctionCode",
                            "lambda:UpdateFunctionConfiguration"
                        ],
                        "Resource": [
                            "arn:aws:lambda:*:*:function:aws-controltower-*"
                        ],
                        "Condition": {
                            "ArnNotLike": {
                                "aws:PrincipalARN": "arn:aws:iam::*:role/AWSControlTowerExecution"
                            }
                        }
                    }
                ]
            },
            guardrails.disallow_lambda_changes()
        )

    def test_disallow_sns_changes(self):
        self.assertEqual(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "GRSNSTOPICPOLICY",
                        "Effect": "Deny",
                        "Action": [
                            "sns:AddPermission",
                            "sns:CreateTopic",
                            "sns:DeleteTopic",
                            "sns:RemovePermission",
                            "sns:SetTopicAttributes"
                        ],
                        "Resource": [
                            "arn:aws:sns:*:*:aws-controltower-*"
                        ],
                        "Condition": {
                            "ArnNotLike": {
                                "aws:PrincipalARN": "arn:aws:iam::*:role/AWSControlTowerExecution"
                            }
                        }
                    }
                ]
            },
            guardrails.disallow_sns_changes()
        )

    def test_disallow_sns_subscriptions_changes(self):
        self.assertEqual(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "GRSNSSUBSCRIPTIONPOLICY",
                        "Effect": "Deny",
                        "Action": [
                            "sns:Subscribe",
                            "sns:Unsubscribe"
                        ],
                        "Resource": [
                            "arn:aws:sns:*:*:aws-controltower-SecurityNotifications"
                        ],
                        "Condition": {
                            "ArnNotLike": {
                                "aws:PrincipalARN": "arn:aws:iam::*:role/AWSControlTowerExecution"
                            }
                        }
                    }
                ]
            },
            guardrails.disallow_sns_subscriptions_changes()
        )

    def test_disallow_creation_of_access_keys_for_root_user(self):
        self.assertEqual(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "GRRESTRICTROOTUSERACCESSKEYS",
                        "Effect": "Deny",
                        "Action": "iam:CreateAccessKey",
                        "Resource": [
                            "*"
                        ],
                        "Condition": {
                            "StringLike": {
                                "aws:PrincipalArn": [
                                    "arn:aws:iam::*:root"
                                ]
                            }
                        }
                    }
                ]
            },
            guardrails.disallow_creation_of_access_keys_for_root_user()
        )

    def test_disallow_actions_of_root_user(self):
        self.assertEqual(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "GRRESTRICTROOTUSER",
                        "Effect": "Deny",
                        "Action": "*",
                        "Resource": [
                            "*"
                        ],
                        "Condition": {
                            "StringLike": {
                                "aws:PrincipalArn": [
                                    "arn:aws:iam::*:root"
                                ]
                            }
                        }
                    }
                ]
            }, guardrails.disallow_root_user_actions())

    def test_ssh_internet_connection(self):
        self.assertEqual(
            {
                "AWSTemplateFormatVersion": "2010-09-09",
                "Description": "Configure AWS Config rules to check whether security groups that are in use disallow SSH",
                "Resources": {
                    "RestrictSSH": {
                        "Type": "AWS::Config::ConfigRule",
                        "Properties": {
                            "ConfigRuleName": 'RestrictSSH',
                            "Description": "Checks whether security groups that are in use disallow unRestrict incoming SSH traffic.",
                            "Scope": {
                                "ComplianceResourceTypes": [
                                    "AWS::EC2::SecurityGroup"
                                ]
                            },
                            "Source": {
                                "Owner": "AWS",
                                "SourceIdentifier": "INCOMING_SSH_DISABLED"
                            }
                        }
                    }
                }
            }, guardrails.disallow_ssh()
        )

    def test_ebs_optimization(self):
        self.assertEqual(
            {
                "AWSTemplateFormatVersion": "2010-09-09",
                "Description": "Configure AWS Config rules to check whether EBS optimization is enabled for your EC2 instances that can be EBS-optimized",
                "Resources": {
                    "OptimizedInstance": {
                        "Type": "AWS::Config::ConfigRule",
                        "Properties": {
                            "ConfigRuleName": 'OptimizedInstance',
                            "Description": "Checks whether EBS optimization is enabled for your EC2 instances that can be EBS-optimized",
                            "Source": {
                                "Owner": "AWS",
                                "SourceIdentifier": "EBS_OPTIMIZED_INSTANCE"
                            },
                            "Scope": {
                                "ComplianceResourceTypes": [
                                    "AWS::EC2::Instance"
                                ]
                            }
                        }
                    }
                }
            },
            guardrails.optimized_ebs_volumes()
        )

    def test_rds_public_access_enabled(self):
        self.assertEqual(
            {
                "AWSTemplateFormatVersion": "2010-09-09",
                "Description": "Configure AWS Config rules to check whether Amazon RDS instances are not publicly accessible.",
                "Resources": {
                    "RDSPublicAccess": {
                        "Type": "AWS::Config::ConfigRule",
                        "Properties": {
                            "ConfigRuleName": 'RDSPublicAccess',
                            "Description": "Checks whether the Amazon Relational Database Service (RDS) instances are not publicly accessible. The rule is non-compliant if the publiclyAccessible field is true in the instance configuration item.",
                            "Source": {
                                "Owner": "AWS",
                                "SourceIdentifier": "RDS_INSTANCE_PUBLIC_ACCESS_CHECK"
                            },
                            "Scope": {
                                "ComplianceResourceTypes": [
                                    "AWS::RDS::DBInstance"
                                ]
                            }
                        }
                    }
                }
            }, guardrails.rds_public_access_enabled()
        )

    def test_root_mfa_enabled(self):
        self.assertEqual(
            {
                "AWSTemplateFormatVersion": "2010-09-09",
                "Description": "Configure AWS Config rules to require MFA for root access to accounts",
                "Resources": {
                    "RootMFA": {
                        "Type": "AWS::Config::ConfigRule",
                        "Properties": {
                            "ConfigRuleName": 'RootMFA',
                            "Description": "Checks whether the root user of your AWS account requires multi-factor authentication for console sign-in.",
                            "Source": {
                                "Owner": "AWS",
                                "SourceIdentifier": "ROOT_ACCOUNT_MFA_ENABLED"
                            },
                            "MaximumExecutionFrequency": 'One_Hour'
                        }
                    }
                }
            },
            guardrails.root_mfa_enabled()
        )

    def test_ebs_attached(self):
        self.assertEqual(
            {
                "AWSTemplateFormatVersion": "2010-09-09",
                "Description": "Configure AWS Config rules to check whether EBS volumes are attached to EC2 instances",
                "Resources": {
                    "EBSAttached": {
                        "Type": "AWS::Config::ConfigRule",
                        "Properties": {
                            "ConfigRuleName": 'EBSAttached',
                            "Description": "Checks whether EBS volumes are attached to EC2 instances",
                            "InputParameters": {
                                "deleteOnTermination": 'true',
                            },
                            "Source": {
                                "Owner": "AWS",
                                "SourceIdentifier": "EC2_VOLUME_INUSE_CHECK"
                            },
                            "Scope": {
                                "ComplianceResourceTypes": [
                                    "AWS::EC2::Volume"
                                ]
                            }
                        }
                    }
                }
            },
            guardrails.ebs_attached()
        )

    def test_restrict_ports(self):
        self.assertEqual(
            {
                "AWSTemplateFormatVersion": "2010-09-09",
                "Description": "Configure AWS Config rules to check whether security groups that are in use disallow unRestrict incoming TCP traffic to the specified ports.",
                "Resources": {
                    "RestrictCommonPorts": {
                        "Type": "AWS::Config::ConfigRule",
                        "Properties": {
                            "ConfigRuleName": "RestrictCommonPorts",
                            "Description": "Checks whether security groups that are in use disallow unRestrict incoming TCP traffic to the specified ports.",
                            "InputParameters": {
                                "blockedPort1": 20,
                                "blockedPort2": 21,
                                "blockedPort3": 3389,
                                "blockedPort4": 3306,
                                "blockedPort5": 4333,
                            },
                            "Scope": {
                                "ComplianceResourceTypes": [
                                    "AWS::EC2::SecurityGroup"
                                ]
                            },
                            "Source": {
                                "Owner": "AWS",
                                "SourceIdentifier": "RESTRICT_INCOMING_TRAFFIC"
                            }
                        }
                    }
                }
            },
            guardrails.tcp_port_restriction()
        )

    def test_ebs_encryption(self):
        self.assertEqual(
            {
                "AWSTemplateFormatVersion": "2010-09-09",
                "Description": "Configure AWS Config rules to check for encryption of all storage volumes attached to compute",
                "Resources": {
                    "EBSEncrypted": {
                        "Type": "AWS::Config::ConfigRule",
                        "Properties": {
                            "ConfigRuleName": 'EBSEncrypted',
                            "Description": "Checks whether EBS volumes that are in an attached state are encrypted.",
                            "Source": {
                                "Owner": "AWS",
                                "SourceIdentifier": "ENCRYPTED_VOLUMES"
                            },
                            "Scope": {
                                "ComplianceResourceTypes": [
                                    "AWS::EC2::Volume"
                                ]
                            }
                        }
                    }
                }
            },
            guardrails.ebs_encryption()
        )

    def test_rds_volume_encryption(self):
        self.assertEqual(
            {
                "AWSTemplateFormatVersion": "2010-09-09",
                "Description": "Configure AWS Config rules to check whether storage encryption is enabled for your RDS DB instances",
                "Resources": {
                    "RDSEncrypted": {
                        "Type": "AWS::Config::ConfigRule",
                        "Properties": {
                            "ConfigRuleName": 'RDSEncrypted',
                            "Description": "Checks whether storage encryption is enabled for your RDS DB instances.",
                            "Source": {
                                "Owner": "AWS",
                                "SourceIdentifier": "RDS_STORAGE_ENCRYPTED"
                            },
                            "Scope": {
                                "ComplianceResourceTypes": [
                                    "AWS::RDS::DBInstance"
                                ]
                            }
                        }
                    }
                }
            },
            guardrails.rds_volume_encryption()
        )


''''
    # https://docs.aws.amazon.com/controltower/latest/userguide/strongly-recommended-guardrails.html
'''
