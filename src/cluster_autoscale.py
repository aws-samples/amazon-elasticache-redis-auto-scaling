import os, sys, random, argparse, logging, time, boto3, requests, json, base64
from rediscluster import RedisCluster
from multiprocessing import Process
from multiprocessing import Pool
from botocore.exceptions import ClientError
import multiprocessing as mp

parser = argparse.ArgumentParser()
parser.add_argument('--cluster_host_name', help='Redis Cluster host name', required=True)
parser.add_argument('--cluster_port', help='Redis Cluster port number', required=True)
parser.add_argument('--secret_name', help='AWS Secrets Manager secret name', required=True)
parser.add_argument('--threads', help='Number threads that should be used', required=True)
args = parser.parse_args()

def redis_connect(secret):
    print('module name:', __name__)
    print('parent process:', os.getppid())
    print('process id:', os.getpid())
    rc = RedisCluster(host=args.cluster_host_name, port=args.cluster_port, decode_responses=True, ssl=True, password=secret, skip_full_coverage_check=True)
    for i in range(10000000):
        key = random.randint(1, sys.maxsize)
        value = random.randint(1, sys.maxsize)
        rc.set(key, value)
        rc.delete(key, value)

def get_secret(secretName):
    # Getting instance identity
    identity = requests.get('http://169.254.169.254/latest/dynamic/instance-identity/document')
    # Getting region from identity
    region = json.loads(identity.text)['region']
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region,
    )
    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secretName
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            print("The requested secret " + secretName + " was not found")
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            print("The request was invalid due to:", e)
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            print("The request had invalid params:", e)
        elif e.response['Error']['Code'] == 'DecryptionFailure':
            print("The requested secret can't be decrypted using the provided KMS key:", e)
        elif e.response['Error']['Code'] == 'InternalServiceError':
            print("An error occurred on service side:", e)
    else:
        # Secrets Manager decrypts the secret value using the associated KMS CMK
        # Depending on whether the secret was a string or binary, only one of these fields will be populated
        # print(get_secret_value_response)
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
        else:
            secret = get_secret_value_response['SecretBinary']
        return json.loads(secret)['password']

if __name__=='__main__':
    print(args.secret_name)
    secret = get_secret(args.secret_name)
    print(secret)
    pool=mp.Pool(int(args.threads))
    for i in range(int(args.threads)):
        p=mp.Process(target=redis_connect,args=(secret,))
        p.start()