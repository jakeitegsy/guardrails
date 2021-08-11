class ConfigRulePolicy:

    def __init__(self, config_rule_name=None, config_rule_description=None, description=None, resource_type=None, maximum_execution_frequency=None, input_parameters=None):
        self.config_rule_name = config_rule_name
        self.config_rule_description = config_rule_description
        self.description = description
        self.resource_type = resource_type
        self.maximum_execution_frequency = maximum_execution_frequency
        self.input_parameters = input_parameters

    def get_config_rule_id(self):
        return {
            'S3PublicRead': 'S3_BUCKET_PUBLIC_READ_PROHIBITED',
            'S3PublicWrite': 'S3_BUCKET_PUBLIC_WRITE_PROHIBITED',
            'RestrictCommonPorts': 'RESTRICT_INCOMING_TRAFFIC',
            'RestrictSSH': 'INCOMING_SSH_DISABLED',
            'OptimizedInstance': 'EBS_OPTIMIZED_INSTANCE',
            'EBSEncrypted': 'ENCRYPTED_VOLUMES',
            'EBSAttached': 'EC2_VOLUME_INUSE_CHECK',
            'RootMFA': 'ROOT_ACCOUNT_MFA_ENABLED',
            'RDSEncrypted': 'RDS_STORAGE_ENCRYPTED',
            'RDSPublicAccess': 'RDS_INSTANCE_PUBLIC_ACCESS_CHECK',
            'IAMUserMFA': 'IAM_USER_MFA_ENABLED',
            'IAMUserConsoleMFA': 'MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS',
            'S3Versioning': 'S3_BUCKET_VERSIONING_ENABLED'
        }.get(self.config_rule_name)

    def config_rule_type(self):
        return {'Type': 'AWS::Config::ConfigRule'}

    def template_version(self):
        return {'AWSTemplateFormatVersion': '2010-09-09'}

    def add_source(self):
        return {
            'Source': {
                'Owner': 'AWS',
                'SourceIdentifier': self.get_config_rule_id()
            }
        }

    def add_resources(self, resources):
        return {'Resources': resources}

    def add_description(self, description):
        return {'Description': description}

    def get_resource_type(resource_type):
        return {
            'EBS': 'AWS::EC2::Volume',
            'EC2': 'AWS::EC2::Instance',
            'S3': 'AWS::S3::Bucket',
            'RDS': 'AWS::RDS::DBInstance',
            'SecurityGroup': 'AWS::EC2::SecurityGroup',
        }.get(resource_type)

    def add_config_rule_name(self):
        return {'ConfigRuleName': self.config_rule_name}

    def get_execution_rule_frequency(self, duration):
        return {
            1: "One_Hour",
            3: "Three_Hours",
            6: "Six_Hours",
            12: "Twelve_Hours",
            24: "TwentyFour_Hours",
        }.get(duration)

    def add_scope(self, scope):
        return add_conditional_dict('Scope', scope)

    def add_maximum_execution_frequency(self):
        return add_conditional_dict(
            'MaximumExecutionFrequency',
            self.get_execution_rule_frequency(self.maximum_execution_frequency)
        )

    def add_scope(self, resource_type):
        return {
            'Scope': {
                'ComplianceResourceTypes': [
                    ConfigRulePolicy.get_resource_type(resource_type)
                ]
            }
        } if resource_type else {}

    def add_input_parameters(self):
        return add_conditional_dict('InputParameters', self.input_parameters)

    def add_properties(self):
        return {
            'Properties': {
                **self.add_config_rule_name(),
                **self.add_description(self.description),
                **self.add_source(),
                **self.add_maximum_execution_frequency(),
                **self.add_scope(self.resource_type),
                **self.add_input_parameters(),
            }
        }

    def generate(self):
        return {
            **self.template_version(),
            **self.add_description(self.config_rule_description),
            **self.add_resources({
                self.config_rule_name: {
                    **self.config_rule_type(),
                    **self.add_properties(),
                }
            })
        }


class ServiceControlPolicy:

    def __init__(self, sid=None, actions=None, resources=None, conditions=None):
        self.sid = sid
        self.actions = actions
        self.resources = resources if resources else ['*']
        self.conditions = conditions

    def get_sid(self, scope):
        return {
            'BucketEncryption': 'GRCTAUDITBUCKETENCRYPTIONCHANGESPROHIBITED',
            'BucketLogging': 'GRCTAUDITBUCKETLOGGINGCONFIGURATIONCHANGESPROHIBITED',
            'BucketPolicy': 'GRCTAUDITBUCKETPOLICYCHANGESPROHIBITED',
            'BucketLifecycle': 'GRCTAUDITBUCKETLIFECYCLECONFIGURATIONCHANGESPROHIBITED',
            'BucketDeletion': 'GRAUDITBUCKETDELETIONPROHIBITED',
            'CloudTrail': 'GRCLOUDTRAILENABLED',
            'CloudWatchLogs': 'GRLOGGROUPPOLICY',
            'ConfigAggregation': 'GRCONFIGAGGREGATIONAUTHORIZATIONPOLICY',
            'Config': 'GRCONFIGENABLED',
            'ConfigRuleTags': 'GRCONFIGRULETAGSPOLICY',
            'ConfigRulePolicy': 'GRCONFIGRULEPOLICY',
            'CloudWatchEvents': 'GRCLOUDWATCHEVENTPOLICY',
            'RolePolicy': 'GRIAMROLEPOLICY',
            'LambdaPolicy': 'GRLAMBDAFUNCTIONPOLICY',
            'SNS': 'GRSNSTOPICPOLICY',
            'SNSSubscriptions': 'GRSNSSUBSCRIPTIONPOLICY',
            'RootAccessKeys': 'GRRESTRICTROOTUSERACCESSKEYS',
            'RootActions': 'GRRESTRICTROOTUSER',
            'EncryptionChanges': 'GRAUDITBUCKETENCRYPTIONENABLED',
            'LoggingChanges': 'GRAUDITBUCKETLOGGINGENABLED',
            'ChangeBucketPolicy': 'GRAUDITBUCKETPOLICYCHANGESPROHIBITED',
            'ChangeLifecycle': 'GRAUDITBUCKETRETENTIONPOLICY',
            'S3ConfigChanges': 'GRRESTRICTS3CROSSREGIONREPLICATION',
            'DeleteS3WithoutMFA': 'GRRESTRICTS3DELETEWITHOUTMFA'
        }.get(scope)

    def control_tower_principal():
        return {'aws:PrincipalARN': role_arn('AWSControlTowerExecution')}

    def control_tower_execution_role_condition():
        return {'ArnNotLike': ServiceControlPolicy.control_tower_principal()}

    def control_tower_resource_tag():
        return {'aws:ResourceTag/aws-control-tower': 'managed-by-control-tower'}

    def version(self):
        return {'Version': '2012-10-17'}

    def add_statement(self, statement):
        return {'Statement': [statement]}

    def add_deny(self):
        return {'Effect': 'Deny'}

    def add_sid(self):
        return {'Sid': self.get_sid(self.sid)}

    def add_actions(self):
        return {'Action': self.actions}

    def add_resources(self):
        return {'Resource': self.resources}

    def add_conditions(self):
        return add_conditional_dict('Condition', self.conditions)

    def add_string_like(value):
        return {'StringLike': value}

    def root_user_condition():
        return ServiceControlPolicy.add_string_like(
            {'aws:PrincipalArn': ['arn:aws:iam::*:root']}
        )

    def generate(self):
        return {
            **self.version(),
            **self.add_statement(
                {
                    **self.add_sid(),
                    **self.add_actions(),
                    **self.add_deny(),
                    **self.add_resources(),
                    **self.add_conditions(),
                }
            )
        }


def add_conditional_dict(key, value):
    return {key: value} if value else {}


def arn(value):
    return f'arn:aws:{value}'


def role_arn(role_name):
    return arn(f'iam::*:role/{role_name}')


def config(action):
    return f'config:{action}'


def events(action):
    return f'events:{action}'


def lambda_function(action):
    return f'lambda:{action}'


def sns(action):
    return f'sns:{action}'


def s3(action):
    return f's3:{action}'


def iam(action):
    return f'iam:{action}'


def cloudtrail(action):
    return f'cloudtrail:{action}'


def create_s3_guardrail(sid, actions=None, conditions=None):
    return ServiceControlPolicy(
        sid=sid,
        actions=actions,
        resources=[arn('s3:::aws-controltower*')],
        conditions=conditions
    ).generate()


def disallow_changes_to_encryption_configuration_for_s3_buckets():
    return create_s3_guardrail(
        'BucketEncryption',
        actions=[s3('PutEncryptionConfiguration')],
        conditions=ServiceControlPolicy.control_tower_execution_role_condition()
    )


def disallow_changes_to_logging_configuration_for_s3_buckets():
    return create_s3_guardrail(
        'BucketLogging',
        actions=[s3('PutBucketLogging')],
        conditions=ServiceControlPolicy.control_tower_execution_role_condition()
    )


def disallow_changes_to_bucket_policy_for_s3_buckets():
    return create_s3_guardrail(
        'BucketPolicy',
        actions=[s3('PutBucketPolicy'), s3('DeleteBucketPolicy')],
        conditions=ServiceControlPolicy.control_tower_execution_role_condition()
    )


def disallow_lifecycle_configuration_changes_to_s3_buckets():
    return create_s3_guardrail(
        'BucketLifecycle',
        actions=[s3('PutLifecycleConfiguration')],
        conditions=ServiceControlPolicy.control_tower_execution_role_condition()
    )


def disallow_S3_delete_without_mfa():
    return ServiceControlPolicy(
        sid='DeleteS3WithoutMFA',
        actions=[s3('DeleteObject'), s3('DeleteBucket')],
        conditions={
            "BoolIfExists": {
                "aws:MultiFactorAuthPresent": [
                    "false"
                ]
            }
        },
    ).generate()


def check_mfa_enabled_for_iam_user():
    return ConfigRulePolicy(
        config_rule_name='IAMUserMFA',
        config_rule_description='Configure AWS Config rules to check whether the IAM users have MFA enabled',
        description="Checks whether the AWS Identity and Access Management users have multi-factor authentication (MFA) enabled. The rule is COMPLIANT if MFA is enabled.",
        maximum_execution_frequency=1
    ).generate()


def check_mfa_enabled_for_iam_user_through_console():
    return ConfigRulePolicy(
        config_rule_name='IAMUserConsoleMFA',
        config_rule_description='Configure AWS Config rules to check whether MFA is enabled for all AWS IAM users that use a console password.',
        description="Checks whether AWS Multi-Factor Authentication (MFA) is enabled for all AWS Identity and Access Management (IAM) users that use a console password. The rule is COMPLIANT if MFA is enabled.",
        maximum_execution_frequency=1
    ).generate()


def disallow_deletion_of_s3_log_archive():
    return create_s3_guardrail(
        'BucketDeletion',
        actions=[s3('DeleteBucket')],
        conditions=ServiceControlPolicy.control_tower_execution_role_condition()
    )


def disallow_encryption_settings_changes_to_s3():
    return ServiceControlPolicy(
        sid='EncryptionChanges',
        actions=[s3('PutEncryptionConfiguration')],
        conditions=ServiceControlPolicy.control_tower_execution_role_condition()
    ).generate()


def disallow_changes_to_s3_logging():
    return ServiceControlPolicy(
        sid='LoggingChanges',
        actions=[s3('PutBucketLogging')],
        conditions=ServiceControlPolicy.control_tower_execution_role_condition()
    ).generate()


def disallow_changes_to_s3_configuration():
    return ServiceControlPolicy(
        sid='S3ConfigChanges',
        actions=[s3('PutReplicationConfiguration')]
    ).generate()


def disallow_changes_to_s3_lifecycle_configuration():
    return ServiceControlPolicy(
        sid='ChangeLifecycle',
        actions=[s3('PutLifecycleConfiguration')],
        conditions=ServiceControlPolicy.control_tower_execution_role_condition()
    ).generate()


def disallow_changes_to_s3_bucket_policy():
    return ServiceControlPolicy(
        sid='ChangeBucketPolicy',
        actions=[s3('PutBucketPolicy')],
        conditions=ServiceControlPolicy.control_tower_execution_role_condition()
    ).generate()


def disallow_deletion_of_config_aggregation_authorizations():
    return ServiceControlPolicy(
        sid='ConfigAggregation',
        actions=[config('DeleteAggregationAuthorization')],
        resources=[arn('config:*:*:aggregation-authorization*')],
        conditions={
            **ServiceControlPolicy.control_tower_execution_role_condition(),
            **ServiceControlPolicy.add_string_like(ServiceControlPolicy.control_tower_resource_tag())
        }
    ).generate()


def enable_cloudtrail():
    return ServiceControlPolicy(
        sid='CloudTrail',
        actions=[
            cloudtrail('DeleteTrail'),
            cloudtrail('PutEventSelectors'),
            cloudtrail('StopLogging'),
            cloudtrail('UpdateTrail')
        ],
        resources=[arn('cloudtrail:*:*:trail/aws-controltower-*')],
        conditions=ServiceControlPolicy.control_tower_execution_role_condition()
    ).generate()


def disallow_cloudwatch_events_changes():
    return ServiceControlPolicy(
        sid='CloudWatchEvents',
        actions=[
            events('PutRule'),
            events('PutTargets'),
            events('RemoveTargets'),
            events('DisableRule'),
            events('DeleteRule'),
        ],
        resources=[arn('events:*:*:rule/aws-controltower-*')],
        conditions=ServiceControlPolicy.control_tower_execution_role_condition()
    ).generate()


def disallow_changes_to_cloudwatch_logs():
    return ServiceControlPolicy(
        sid='CloudWatchLogs',
        actions=['logs:DeleteLogGroup', 'logs:PutRetentionPolicy'],
        resources=[arn('logs:*:*:log-group:*aws-controltower*')],
        conditions={
            'StringNotLike': ServiceControlPolicy.control_tower_principal()
        },
    ).generate()


def disallow_config_rule_tag_changes():
    return ServiceControlPolicy(
        sid='ConfigRuleTags',
        actions=[
            config('TagResource'),
            config('UntagResource')
        ],
        conditions={
            **ServiceControlPolicy.control_tower_execution_role_condition(),
            'ForAllValues:StringEquals': {
                'aws:TagKeys': 'aws-control-tower'
            }
        }
    ).generate()


def enable_config():
    return ServiceControlPolicy(
        sid='Config',
        actions=[
            config('DeleteConfigurationRecorder'),
            config('DeleteDeliveryChannel'),
            config('DeleteRetentionConfiguration'),
            config('PutConfigurationRecorder'),
            config('PutDeliveryChannel'),
            config('PutRetentionConfiguration'),
            config('StopConfigurationRecorder'),
        ],
        conditions=ServiceControlPolicy.control_tower_execution_role_condition()
    ).generate()


def disallow_config_rule_changes():
    return ServiceControlPolicy(
        sid='ConfigRulePolicy',
        actions=[
            config('PutConfigRule'),
            config('DeleteConfigRule'),
            config('DeleteEvaluationResults'),
            config('DeleteConfigurationAggregator'),
            config('PutConfigurationAggregator'),
        ],
        conditions={
            **ServiceControlPolicy.control_tower_execution_role_condition(),
            'StringEquals': ServiceControlPolicy.control_tower_resource_tag()
        }
    ).generate()


def iam_role_policy():
    return ServiceControlPolicy(
        sid='RolePolicy',
        actions=[
            iam('AttachRolePolicy'),
            iam('CreateRole'),
            iam('DeleteRole'),
            iam('DeleteRolePermissionsBoundary'),
            iam('DeleteRolePolicy'),
            iam('DetachRolePolicy'),
            iam('PutRolePermissionsBoundary'),
            iam('PutRolePolicy'),
            iam('UpdateAssumeRolePolicy'),
            iam('UpdateRole'),
            iam('UpdateRoleDescription'),
        ],
        resources=[
            role_arn('aws-controltower-*'),
            role_arn('*AWSControlTower*'),
            role_arn('stacksets-exec-*'),
        ],
        conditions={
            'ArnNotLike': {
                'aws:PrincipalArn': [
                    role_arn('AWSControlTowerExecution'),
                    role_arn('stacksets-exec-*')
                ]
            }
        }
    ).generate()


def disallow_lambda_changes():
    return ServiceControlPolicy(
        sid='LambdaPolicy',
        actions=[
            lambda_function('AddPermission'),
            lambda_function('CreateEventSourceMapping'),
            lambda_function('CreateFunction'),
            lambda_function('DeleteEventSourceMapping'),
            lambda_function('DeleteFunction'),
            lambda_function('DeleteFunctionConcurrency'),
            lambda_function('PutFunctionConcurrency'),
            lambda_function('RemovePermission'),
            lambda_function('UpdateEventSourceMapping'),
            lambda_function('UpdateFunctionCode'),
            lambda_function('UpdateFunctionConfiguration'),
        ],
        resources=[arn('lambda:*:*:function:aws-controltower-*')],
        conditions=ServiceControlPolicy.control_tower_execution_role_condition()
    ).generate()


def disallow_sns_changes():
    return ServiceControlPolicy(
        sid='SNS',
        actions=[
            sns('AddPermission'),
            sns('CreateTopic'),
            sns('DeleteTopic'),
            sns('RemovePermission'),
            sns('SetTopicAttributes'),
        ],
        resources=[arn('sns:*:*:aws-controltower-*')],
        conditions=ServiceControlPolicy.control_tower_execution_role_condition()
    ).generate()


def disallow_sns_subscriptions_changes():
    return ServiceControlPolicy(
        sid='SNSSubscriptions',
        actions=[
            sns('Subscribe'),
            sns('Unsubscribe')
        ],
        resources=[arn('sns:*:*:aws-controltower-SecurityNotifications')],
        conditions=ServiceControlPolicy.control_tower_execution_role_condition()
    ).generate()


def disallow_creation_of_access_keys_for_root_user():
    return ServiceControlPolicy(
        sid='RootAccessKeys',
        actions=iam('CreateAccessKey'),
        conditions=ServiceControlPolicy.root_user_condition()
    ).generate()


def disallow_root_user_actions():
    return ServiceControlPolicy(
        sid='RootActions',
        actions='*',
        conditions=ServiceControlPolicy.root_user_condition()
    ).generate()


def config_rule_for_s3_public_read_access():
    return ConfigRulePolicy(
        config_rule_name='S3PublicRead',
        config_rule_description='Configure AWS Config rules to check that your S3 buckets do not allow public access',
        description='Checks that your S3 buckets do not allow public read access. If an S3 bucket policy or bucket ACL allows public read access, the bucket is noncompliant.',
        resource_type='S3'
    ).generate()


def config_rule_for_s3_public_write_access():
    return ConfigRulePolicy(
        config_rule_name='S3PublicWrite',
        config_rule_description='Configure AWS Config rules to check that your S3 buckets do not allow public access',
        description='Checks that your S3 buckets do not allow public write access. If an S3 bucket policy or bucket ACL allows public write access, the bucket is noncompliant.',
        resource_type='S3'
    ).generate()


def versioning_enabled():
    return ConfigRulePolicy(
        config_rule_name='S3Versioning',
        config_rule_description='Configure AWS Config rules to check whether versioning is enabled for your S3 buckets.',
        description='Checks whether versioning is enabled for your S3 buckets.',
        resource_type='S3'
    ).generate()


def disallow_ssh():
    return ConfigRulePolicy(
        config_rule_name='RestrictSSH',
        config_rule_description='Configure AWS Config rules to check whether security groups that are in use disallow SSH',
        description='Checks whether security groups that are in use disallow unRestrict incoming SSH traffic.',
        resource_type='SecurityGroup'
    ).generate()


def ebs_attached():
    return ConfigRulePolicy(
        config_rule_name='EBSAttached',
        config_rule_description='Configure AWS Config rules to check whether EBS volumes are attached to EC2 instances',
        description='Checks whether EBS volumes are attached to EC2 instances',
        input_parameters={"deleteOnTermination": 'true'},
        resource_type='EBS'
    ).generate()


def optimized_ebs_volumes():
    return ConfigRulePolicy(
        config_rule_name='OptimizedInstance',
        config_rule_description='Configure AWS Config rules to check whether EBS optimization is enabled for your EC2 instances that can be EBS-optimized',
        description='Checks whether EBS optimization is enabled for your EC2 instances that can be EBS-optimized',
        resource_type='EC2'
    ).generate()


def rds_public_access_enabled():
    return ConfigRulePolicy(
        config_rule_name='RDSPublicAccess',
        config_rule_description='Configure AWS Config rules to check whether Amazon RDS instances are not publicly accessible.',
        description='Checks whether the Amazon Relational Database Service (RDS) instances are not publicly accessible. The rule is non-compliant if the publiclyAccessible field is true in the instance configuration item.',
        resource_type='RDS'
    ).generate()


def root_mfa_enabled():
    return ConfigRulePolicy(
        config_rule_name='RootMFA',
        config_rule_description='Configure AWS Config rules to require MFA for root access to accounts',
        description='Checks whether the root user of your AWS account requires multi-factor authentication for console sign-in.',
        maximum_execution_frequency=1,
    ).generate()


def tcp_port_restriction():
    return ConfigRulePolicy(
        config_rule_name='RestrictCommonPorts',
        config_rule_description='Configure AWS Config rules to check whether security groups that are in use disallow unRestrict incoming TCP traffic to the specified ports.',
        resource_type='SecurityGroup',
        description='Checks whether security groups that are in use disallow unRestrict incoming TCP traffic to the specified ports.',
        input_parameters={
            "blockedPort1": 20,
            "blockedPort2": 21,
            "blockedPort3": 3389,
            "blockedPort4": 3306,
            "blockedPort5": 4333,
        }
    ).generate()


def ebs_encryption():
    return ConfigRulePolicy(
        config_rule_name='EBSEncrypted',
        config_rule_description='Configure AWS Config rules to check for encryption of all storage volumes attached to compute',
        description='Checks whether EBS volumes that are in an attached state are encrypted.',
        resource_type='EBS'
    ).generate()


def rds_volume_encryption():
    return ConfigRulePolicy(
        config_rule_name='RDSEncrypted',
        config_rule_description='Configure AWS Config rules to check whether storage encryption is enabled for your RDS DB instances',
        description='Checks whether storage encryption is enabled for your RDS DB instances.',
        resource_type='RDS',
    ).generate()
