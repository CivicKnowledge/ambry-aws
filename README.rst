# ambry-aws

Create and manage S3 buckets and users for use as Ambry library repositories.

With these commands, you can create new buckets, initialized them with sub-directories for bundles of different access levels, and manage users that can access those sub-directories.

The buckets are created with these sub-directories:

* private
* public
* restricted
* system
* test

For each of these sub-directories, the 'init-bucket' command will create two groups, a read group and a read-write group.

New users will be created with the `/ambry/` path, although you can set permissions for any users, even those not created through this API.

# Use Examples

Setup a profile in the credentials, probably by editing your `~/.aws/credentials` file. The credentials must be for a user that can create buckets and users, probably one with the Administrator permissions.

Create a new bucket

  $ ambry aws <profile> init-bucket foobunk.example.com

List the buckets with `ambry aws <profile> list-buckets` to see that the bucket was created.

Create a new user

  $ ambry aws <profile> new-user bobson

The command will print the new users' access key and secret key to the console.

Give the user permissions

  $ ambry aws <profile> perm bobson    foobunk.example.com/private # read
  $ ambry aws <profile> perm bobson -w foobunk.example.com/restricted # read and write

List the users and the permissions. This will only show users created through this interface:

  $ ambry aws <profile> list-users

  bobson
    foobunk-example-com-private-r
    foobunk-example-com-restricted-rw


Test all of the user's permissions against a bucket:

  $ ambry aws <profile> test-user bobson foobunk.example.com

Be sure to [setup your AWS credentials for boto](https://boto3.readthedocs.org/en/latest/guide/quickstart.html).


Operations

* Initialize
    ** Create a bucket with standard Ambry remote categories: system, test, public, restricted, private
    ** Create groups with policies for each remote category on the bucket, read and write.
* Create a new user
* Add or remove a user to a group

