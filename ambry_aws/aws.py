

from __future__ import absolute_import

__all__ = ['command_name', 'make_parser', 'run_command']
command_name = 'aws'

from ambry.cli import prt, fatal, warn, err


def make_parser(cmd):

    config_p = cmd.add_parser(command_name, help='Manage AWS resources for Ambry')
    config_p.set_defaults(command=command_name)

    config_p.add_argument('profile_name', type=str, help='Name of boto/aws credentials file')
    asp = config_p.add_subparsers(title='AWS commands', help='AWS commands')

    sp = asp.add_parser('list-buckets', help="List buckets")
    sp.set_defaults(subcommand=list_remotes)

    sp = asp.add_parser('list-users', help="List users")
    sp.set_defaults(subcommand=list_users)

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


USER_PATH='/ambry/'
TOP_LEVEL_DIRS = ('system','test','public','restricted','private')

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
        r = client.create_user(Path=USER_PATH, UserName=args.user_name)

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

        for group in user.groups.all():
            prt("Removing user from group: {}",group.name)
            user.remove_group(GroupName=group.name)

        response = client.delete_user(UserName=args.user_name)
        prt("Deleted user: {}".format(args.user_name))

    except ClientError as e:
        fatal("Could not delete user: {}".format(e))


def init_bucket(args, l, rc):
    from botocore.exceptions import ClientError

    s3 = get_resource(args, 's3')
    iam = get_resource(args, 'iam')

    b = s3.Bucket(args.bucket_name)

    clean_cb_name = args.bucket_name.replace('.','-')

    r = b.create()

    for prefix in TOP_LEVEL_DIRS:
        for write in (True, False):

            gp_name = "{}-{}-{}".format(clean_cb_name,prefix, 'rw' if write else 'r')

            group = iam.Group(gp_name)
            try:
                r = group.create()
            except ClientError as e:
                print '!!!', e, dir(e)

            policy = group.Policy(gp_name)
            policy.put(PolicyDocument=make_group_policy(b.name, prefix, write))

def make_group_name(bucket_name, prefix, write):

    clean_cb_name = bucket_name.replace('.', '-')

    gn =  "{}-{}-{}".format(clean_cb_name, prefix, 'rw' if write else 'r')

    return gn

def split_bucket_name(bucket, default = 'public'):
    if '/' in bucket:
        bn, prefix = bucket.split('/')
    else:
        bn = bucket
        prefix = default

    return bn, prefix



def perm(args, l, rc):

    s3 = get_resource(args, 's3')
    iam = get_resource(args, 'iam')

    bn, prefix = split_bucket_name(args.bucket)

    user = iam.User(args.user_name)

    if args.delete:
        user.remove_group(GroupName=make_group_name(bn, prefix, args.write))
    else:

        if args.write:
            # If adding write, remove the read group
            user.remove_group(GroupName=make_group_name(bn, prefix, False))

        user.add_group(GroupName=make_group_name(bn, prefix, args.write))


def list_users(args, l, rc):

    client = get_client(args, 'iam')
    iam = get_resource(args, 'iam')

    users = client.list_users(PathPrefix=USER_PATH)

    for user_info in users['Users']:

        user = iam.User(user_info['UserName'])
        print user.name
        for group in user.groups.all():
            print "   ", group.name


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


    session = boto3.Session(aws_access_key_id=account.access_key,
                            aws_secret_access_key=account.secret)

    root_s3 = get_resource(args, 's3')
    s3 = session.resource('s3')

    bn, prefix = split_bucket_name(args.bucket, default = None)

    root_bucket = root_s3.Bucket(bn)
    bucket = s3.Bucket(bn)

    prefixes = [prefix] if prefix else TOP_LEVEL_DIRS

    for prefix in prefixes:
        k = prefix+'/test'+args.user_name
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

        prt("{:<25s} {:<5s} {:<5s} {:<6s} {}".format(k, 'read' if read else '',
                                                  'write' if write else '',
                                                  'delete' if delete else '',
                                                  'no access' if not any((read, write, delete)) else '' ))


    return

    def get_statement(name):
        for s in doc['Statement']:
            if s['Sid'] == name:
                return s

    for group in user.groups.all():
        for policy in group.policies.all():
            doc = policy.policy_document

            read = get_statement('read')
            for resource in read['Resource']:
                resource = resource.replace('arn:aws:s3:::','').replace('/*','')
                print resource

                bucket, prefix = resource.split('/')

                print "READ", bucket, prefix

            write = get_statement('write')
            if write:
                for resource in read['Resource']:
                    resource = resource.replace('arn:aws:s3:::', '').replace('/*', '')

                    bucket, prefix = resource.split('/')

                    print "READ", bucket, prefix



