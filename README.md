# jcredstash
A pure Java implementation of the CredStash utility originally in Python

This code is left here for mostly historical purposes. If it continues to be useful, feel free to use it, but I recommend migrating away from Credstash. We discovered the following issue which broke compatibility. There was no clean way to write a new client that could read/write secrets with the original client across versions. The solution was to restrict people to only using old versions of the python client for editing secrets.

https://github.com/fugue/credstash/issues/154

Please consider using a wholely AWS solution that is much more likely to maintain compatibility.

https://aws.amazon.com/blogs/compute/managing-secrets-for-amazon-ecs-applications-using-parameter-store-and-iam-roles-for-tasks/
