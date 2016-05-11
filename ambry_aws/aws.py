

# Copyright (c) 2016 Civic Knowledge. This file is licensed under the terms of the
# Revised BSD License, included in this distribution as LICENSE


from __future__ import absolute_import

__all__ = ['command_name', 'make_parser', 'run_command']
command_name = 'aws'

from ambry.cli import prt, fatal, warn, err


def make_parser(cmd):

    config_p = cmd.add_parser(command_name, help='Manage AWS resources for Ambry')
    config_p.set_defaults(command=command_name)

    config_p.add_argument('profile_name', type=str, nargs='?', help='Name of boto/aws credentials file')
    asp = config_p.add_subparsers(title='AWS commands', help='AWS commands')

    sp = asp.add_parser('config', help="List AWS configuration profiles, from the standard BOTO config locations")
    sp.set_defaults(subcommand=config)

    sp = asp.add_parser('list-buckets', help="List buckets")
    sp.set_defaults(subcommand=list_remotes)

    sp = asp.add_parser('list-users', help="List users")
    sp.set_defaults(subcommand=list_users)

    sp = asp.add_parser('list-bucket-users', help="List users with permissions on a bucket")
    sp.set_defaults(subcommand=list_bucket_users)
    sp.add_argument('bucket', help='Bucket name')

    sp = asp.add_parser('init-bucket', help="Initialize ambry buckets")
    sp.set_defaults(subcommand=init_bucket)
    sp.add_argument('bucket_name', help='Bucket name')

    sp = asp.add_parser('new-user', help="Create a new IAM user")
    sp.set_defaults(subcommand=new_user)
    sp.add_argument('user_name', help='User name')

    sp = asp.add_parser('delete-user', help="Delete an IAM user")
    sp.set_defaults(subcommand=delete_user)
    sp.add_argument('user_name', help='User name')

    sp = asp.add_parser('perm', help="Add a permission to a user on a bucket")
    sp.set_defaults(subcommand=perm)
    sp.add_argument('-w', '--write', default=False, action='store_true', help="Also add write permission")
    sp.add_argument('-d', '--delete', default=False, action='store_true', help="Remove the permission instead")
    sp.add_argument('user_name', help='User name')
    sp.add_argument('bucket', help='Bucket name, possibly with prefix')

    sp = asp.add_parser('test-user', help="Test user access")
    sp.set_defaults(subcommand=test_user)
    sp.add_argument('user_name', help='User name')
    sp.add_argument('bucket', help='Bucket name')

    sp = asp.add_parser('remotes', help="Dump remotes configuration for a user")
    sp.set_defaults(subcommand=remotes)
    sp.add_argument('user_name', help='User name')

    sp = asp.add_parser('test', help="Development test")
    sp.set_defaults(subcommand=test)


AMBRY_PATH='/ambry/'
TOP_LEVEL_DIRS = ('system','test','public','restricted','private')

policy_name = 'ambry-s3' # User policy name

def run_command(args, rc):
    from ambry.library import new_library
    from ambry.cli import global_logger

    try:
        l = new_library(rc)
        l.logger = global_logger
    except Exception as e:
        warn('No library: {}'.format(e))
        l = None

    args.subcommand(args, l, rc) # Note the calls to sp.set_defaults(subcommand=...)

def get_client(cli_args, service, *args, **kwargs):
    import boto3
    session = boto3.Session(profile_name=cli_args.profile_name)

    return session.client(service, *args, **kwargs)

def get_resource(cli_args, service, *args, **kwargs):
    import boto3
    session = boto3.Session(profile_name=cli_args.profile_name)

    return session.resource(service, *args, **kwargs)

def config(args, l, rc):

    import ConfigParser
    import os
    from os.path import expanduser
    import tabulate

    records =  []
    headers = 'File Section Access'.split()

    if os.getenv('AWS_ACCESS_KEY_ID',''):
        records.append(['env', 'env', os.getenv('AWS_ACCESS_KEY_ID','')])

    for fn in ('~/.aws/credentials','~/.aws/config','/etc/boto.cfg','~/.boto'):
        config = ConfigParser.ConfigParser()
        config.read(expanduser(fn))
        for s in config.sections():
            try:
                records.append([fn,s,config.get(s,'aws_access_key_id')])
            except ConfigParser.NoOptionError:
                pass

    print tabulate.tabulate(records, headers=headers)


def list_remotes(args, l, rc):

    client = get_client(args, 's3')

    r = client.list_buckets()
    for e in r['Buckets']:
        print e['Name']


def new_user(args, l, rc):


    from botocore.exceptions import ClientError

    client = get_client(args, 'iam')

    try:
        r = client.get_user(UserName=args.user_name)
        prt("User already exists")

    except ClientError:
        r = client.create_user(Path=AMBRY_PATH, UserName=args.user_name)

        iam = get_resource(args, 'iam')

        user_name = r['User']['UserName']

        user = iam.User(user_name)

        key_pair = user.create_access_key_pair()

        account = l.find_or_new_account(user.arn)
        account.name = user.user_name
        account.major_type = 'iam'
        account.access_key = key_pair.id
        account.secret = key_pair.secret
        l.commit()

        prt("Created user : {}", user.user_name )
        prt("arn          : {}", user.arn)
        prt("Access Key   : {}", key_pair.id)
        prt("Secret Key   : {}", key_pair.secret)

def make_group_policy(bucket, prefix, write=False):
    import json
    import ambry_aws
    from os.path import dirname, join, abspath

    policy_path = join(dirname(abspath(ambry_aws.__file__)), 'support', 'group-policy.json')

    with open(policy_path) as f:
        policy_doc = f.read()

    doc = json.loads(policy_doc)

    arn='arn:aws:s3:::'

    def get_statement(name):
        for s in doc['Statement']:
            if s['Sid'] == name:
                return s

    def del_statement(name):
        for i, s in enumerate(doc['Statement']):
            if s['Sid'] == name:
                del doc['Statement'][i]

    get_statement('bucket')['Resource'].append(arn+bucket)
    get_statement('read')['Resource'].append(arn+bucket+'/'+prefix.strip('/')+'/*')

    if write:
        get_statement('write')['Resource'].append(arn + bucket + '/' + prefix.strip('/') + '/*')
    else:
        del_statement('write')


    return json.dumps(doc)

arn_prefix = 'arn:aws:s3:::'

def user_dict_to_policy(d):

    import json
    import ambry_aws
    from os.path import dirname, join, abspath



    policy_path = join(dirname(abspath(ambry_aws.__file__)), 'support', 'user-policy.json')

    with open(policy_path) as f:
        policy_doc = f.read()

    doc = json.loads(policy_doc)

    buckets = set()
    reads = set()
    writes = set()

    for (bucket, prefix), mode in d.items():

        buckets.add(bucket)

        if mode == 'R':
            reads.add((bucket, prefix))
        elif mode == 'W':
            reads.add((bucket, prefix))
            writes.add((bucket, prefix))


    # Get a reference to a read, write or bucket statement
    def get_statement(name):
        for s in doc['Statement']:
            if s['Sid'] == name:
                return s

    get_statement('list')['Resource'] = [arn_prefix + b for b in buckets]
    get_statement('bucket')['Resource'] = [arn_prefix + b for b in buckets]
    get_statement('read')['Resource'] = ["{}{}/{}/*".format(arn_prefix,b,p) for b, p in reads]

    if writes:
        get_statement('write')['Resource'] = ["{}{}/{}/*".format(arn_prefix, b, p) for b, p in writes]
    else:
        # Can't have a section with no resources
        doc['Statement'] = [s for s in doc['Statement'] if s['Sid'] != 'write']

    # Add permission to list buckets with read access
    from collections import defaultdict
    prefixes_per_bucket = defaultdict(set)
    for (bucket, prefix) in reads:
        prefixes_per_bucket[bucket].add(prefix)

    for bucket, prefixes in prefixes_per_bucket.items():

        doc['Statement'].append(
            {
                "Sid": "List{}".format( ''.join(p.title() for p in bucket.split('.'))),
                "Action": ["s3:ListBucket"],
                "Effect": "Allow",
                "Resource": ["{}{}".format(arn_prefix,bucket)],
                "Condition": {"StringLike": {"s3:prefix": ["{}/*".format(prefix) for prefix in prefixes]}}
            }
        )

    return json.dumps(doc, indent=4)

def user_policy_to_dict(doc):
    """Convert a bucket policy to a dict mapping principal/prefix names to 'R' or 'W' """

    import json

    if not isinstance(doc, dict):
        doc = json.loads(doc)

    d = {}

    def get_statement(name):
        for s in doc['Statement']:
            if s['Sid'] == name:
                return s

    for r in get_statement('read')['Principal']['AWS']:
        bucket, prefix = r.replace(arn_prefix,'').replace('/*','').split('/')
        d[(bucket, prefix.strip('/'))] = 'R'

    try:
        for r in get_statement('write')['Resource']:
            bucket, prefix = r.replace(arn_prefix, '').replace('/*','').split('/')
            d[(bucket, prefix.strip('/'))] = 'W'
    except TypeError:
        pass # No write section

    return d

def make_bucket_policy_statements(bucket):
    """Return the statemtns in a bucket policy as a dict of dicts"""
    import yaml
    import ambry_aws
    from os.path import dirname, join, abspath
    import copy

    with open(join(dirname(abspath(ambry_aws.__file__)), 'support', 'policy_parts.yaml')) as f:
        parts = yaml.load(f)

    statements = {}

    cl = copy.deepcopy(parts['list'])
    cl['Resource'] = arn_prefix+bucket
    statements['list'] = cl

    cl = copy.deepcopy(parts['bucket'])
    cl['Resource'] = arn_prefix + bucket
    statements['bucket'] = cl

    for sd in TOP_LEVEL_DIRS:
        cl = copy.deepcopy(parts['read'])
        cl['Resource'] = arn_prefix + bucket +'/' + sd + '/*'
        cl['Sid'] = cl['Sid'].title()+sd.title()

        statements[cl['Sid']] = cl

        cl = copy.deepcopy(parts['write'])
        cl['Resource'] = arn_prefix + bucket +'/' + sd + '/*'
        cl['Sid'] = cl['Sid'].title() + sd.title()

        statements[cl['Sid']] = cl

    return statements

def bucket_dict_to_policy(args, bucket_name, d):
    """
    Create a bucket policy document from a permissions dict.

    The dictionary d maps (user, prefix) to 'R' or 'W'.

    :param bucket_name:
    :param d:
    :return:
    """

    import json
    import ambry_aws
    from os.path import dirname, join, abspath

    iam = get_resource(args, 'iam')

    statements = make_bucket_policy_statements(bucket_name)

    user_stats = set() # statement tripples

    for (user, prefix), mode in d.items():

        user_stats.add((user, 'list'))
        user_stats.add((user, 'bucket'))

        if mode == 'R':
            user_stats.add((user, 'Read' + prefix.title()))
        elif mode == 'W':
            user_stats.add((user, 'Read' + prefix.title()))
            user_stats.add((user, 'Write' + prefix.title()))

    users_arns = {}

    for user_name, section in user_stats:
        section = statements[section]

        if user_name not in users_arns:
            user = iam.User(user_name)
            users_arns[user.name] = user
        else:
            user = users_arns[user_name]

        section['Principal']['AWS'].append(user.arn)

    for sid in statements.keys():
        if not statements[sid]['Principal']['AWS']:
            del statements[sid]

    return json.dumps(dict(Version="2012-10-17", Statement=list(statements.values())), indent=4)

def bucket_policy_to_dict(policy):
    """Produce a dictionary of read, write permissions for an existing bucket policy document"""
    import json

    if not isinstance(policy, dict):
        policy = json.loads(policy)

    statements = { s['Sid']:s for s in policy['Statement'] }

    d = {}

    for rw in ('Read', 'Write'):
        for prefix in TOP_LEVEL_DIRS:
            sid = rw.title() + prefix.title()

            if sid in statements:

                if isinstance(statements[sid]['Principal']['AWS'], list):

                    for principal in statements[sid]['Principal']['AWS']:

                        user_name = principal.split('/').pop()
                        d[(user_name, prefix)] = rw[0]
                else:
                    user_name = statements[sid]['Principal']['AWS'].split('/').pop()
                    d[(user_name, prefix)] = rw[0]

    return d


def delete_user(args, l, rc):
    from botocore.exceptions import ClientError

    client = get_client(args, 'iam')

    try:
        resource = get_resource(args, 'iam')
        user = resource.User(args.user_name)

        for key in user.access_keys.all():
            prt("Deleting user key: {}",key)
            key.delete()

        for policy in user.policies.all():
            prt("Deleting user policy: {}",policy.name)
            policy.delete()

        response = client.delete_user(UserName=args.user_name)
        prt("Deleted user: {}".format(args.user_name))

    except ClientError as e:
        fatal("Could not delete user: {}".format(e))




def init_bucket(args, l, rc):
    from botocore.exceptions import ClientError
    import json

    s3 = get_resource(args, 's3')

    b = s3.Bucket(args.bucket_name)

    b.create()


def split_bucket_name(bucket, default = 'public'):

    if '/' in bucket:
        bn, prefix = bucket.split('/')
    elif default != False:
        bn = bucket
        prefix = default
    else:
        bn = bucket
        prefix = None

    return bn, prefix


def perm(args, l, rc):

    from botocore.exceptions import ClientError
    import json

    iam = get_resource(args, 'iam')

    bn, prefix = split_bucket_name(args.bucket, default = False)

    if not prefix:
        prefixes = TOP_LEVEL_DIRS
    else:
        prefixes = [prefix]

    user = iam.User(args.user_name)

    b = get_resource(args, 's3').Bucket(bn)

    try:

        bucket_policy = b.Policy().policy
        perms = bucket_policy_to_dict(bucket_policy)

    except ClientError:
        perms = {}
        bucket_policy = None

    for prefix in prefixes:
        if args.delete:
            if (user.arn, prefix) in perms:
                del perms[(user.name, prefix)]
                prt("Removed {}/{} from {}".format(bn, prefix, user.name))
        else:

            if args.write:
                perms[(user.name, prefix)] = 'W'
                prt("Added write {}/{} to {}".format(bn, prefix, user.name))
                has_writes = True
            else:
                perms[(user.name, prefix)] = 'R'
                prt("Added read {}/{} to {}".format(bn, prefix, user.name))

    if perms:
        b = get_resource(args, 's3').Bucket(bn)
        policy = bucket_dict_to_policy(args, bn, perms)
        b.Policy().put(Policy=policy)

    elif bucket_policy:
        bucket_policy.delete()


def list_users(args, l, rc):
    from botocore.exceptions import ClientError
    import tabulate

    client = get_client(args, 'iam')
    iam = get_resource(args, 'iam')

    records = []
    headers = 'Name ARN'.split()

    users = client.list_users(PathPrefix='/')

    for user_info in users['Users']:

        user = iam.User(user_info['UserName'])

        records.append([user.name, user.arn])

    print tabulate.tabulate(records, headers)

def list_bucket_users(args, l, rc):
    from botocore.exceptions import ClientError
    import tabulate

    client = get_client(args, 'iam')
    iam = get_resource(args, 'iam')

    b = get_resource(args, 's3').Bucket(args.bucket)

    perms = bucket_policy_to_dict(b.Policy().policy)

    records = []
    headers = ['Name'] + list(TOP_LEVEL_DIRS)

    users = client.list_users(PathPrefix='/')

    for user_info in users['Users']:

        user = iam.User(user_info['UserName'])

        row = [user.name]

        for prefix in TOP_LEVEL_DIRS:
            row.append(perms.get((user.name, prefix)))

        records.append(row)

    print tabulate.tabulate(records, headers)

def get_iam_account(l, args, user_name):
    """Return the local Account for a user name, by fetching User and looking up
    the arn. """

    iam = get_resource(args, 'iam')
    user = iam.User(user_name)
    user.load()

    return l.find_or_new_account(user.arn)

def test_user(args, l, rc):
    from botocore.exceptions import ClientError
    import boto3

    account = get_iam_account(l, args, args.user_name)

    if not account.access_key:
        fatal("Can't test user {}; library does not have record for account ( by arn ) ".format(args.user_name))

    session = boto3.Session(aws_access_key_id=account.access_key,
                            aws_secret_access_key=account.secret)

    root_s3 = get_resource(args, 's3')
    s3 = session.resource('s3')

    bn, prefix = split_bucket_name(args.bucket, default = None)

    root_bucket = root_s3.Bucket(bn)
    bucket = s3.Bucket(bn)

    prefixes = [prefix] if prefix else TOP_LEVEL_DIRS

    for prefix in prefixes:
        k = prefix+'/test/'+args.user_name
        rk = k+'-root'

        ro = root_bucket.put_object(Key=rk, Body=args.user_name)

        try:
            o = bucket.Object(rk)
            c = o.get()
            read = True
        except ClientError as e:
            read = False

        try:
            o = bucket.put_object(Key=k, Body=args.user_name)
            write = True
        except ClientError as e:
            write = False

        try:
            o.delete()
            delete = True
        except ClientError as e:
            delete = False

        #ro.delete()

        prt("{:<35s} {:<5s} {:<5s} {:<6s} {}".format(k, 'read' if read else '',
                                                  'write' if write else '',
                                                  'delete' if delete else '',
                                                  'no access' if not any((read, write, delete)) else '' ))


def remotes(args, l, rc):
    import yaml
    from botocore.exceptions import ClientError

    iam = get_resource(args, 'iam')

    user = iam.User(args.user_name)

    try:
        policy = user.Policy(policy_name)
        perms = policy_to_dict(policy.policy_document)

    except ClientError:
        perms = {}
        policy = None

    account = get_iam_account(l, args, args.user_name)

    remotes = {}

    for i, ((bucket, prefix), perm) in enumerate(perms.items()):

        if prefix not in remotes:
            name = prefix
        else:
            name = "{}{}".format(prefix,i)

        remotes[name]={
            'service': 's3',
            'username': user.arn,
            'url': "s3://{}/{}".format(bucket, prefix),
            'access': account.access_key,
            'secret': account.secret
        }


    print yaml.safe_dump({'remotes': remotes},
                    default_flow_style=False, indent=4, encoding='utf-8')


def test(args, l, rc):

    p = bucket_dict_to_policy(args, 'analysis.civicknowledge.org',{
        ('eric', 'public'): 'R',
        ('eric', 'private'): 'W',
        ('eric-devel', 'public'): 'R',
        ('eric-devel', 'private'): 'W',
        ('eric-devel', 'restricted'): 'W',
    })

    print bucket_policy_to_dict(p)


