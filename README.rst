# ambry-aws

Commands for managing AWS resources for Ambry

Be sure to [setup your AWS credentials for boto](https://boto3.readthedocs.org/en/latest/guide/quickstart.html).


Operations

* Initialize
    ** Create a bucket with standard Ambry remote categories: system, test, public, restricted, private
    ** Create groups with policies for each remote category on the bucket, read and write.
* Create a new user
* Add or remove a user to a group

