import sys
import os
import json
import ziputil
import time
from uuid import uuid4
from requests_factory import RequestFactory
from base64 import b64encode
from cryptography.hazmat.backends import default_backend as new_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import ciphers
from cryptography.hazmat.primitives.ciphers import aead
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key


AES_BITS = 128
GCM_NONCE_LENGTH = 12

IRONWORKER_URL = 'https://worker-aws-us-east-1.iron.io'
IRONWORKER_VERSION = 2


class IronWorker(RequestFactory):
    def __init__(
            self,
            token,
            base_url=IRONWORKER_URL,
            api_version=IRONWORKER_VERSION):
        super(IronWorker, self).__init__()
        self.set_base_url(base_url)\
            .add_url(str(api_version))\
            .set_auth(' '.join(['OAuth', str(token)]))\
            .accept_json()\
            .application_json()

    def clusters(self, *args, **kwargs):
        return self.request('clusters', *args).set_query(jwt=kwargs['jwt'])

    def projects(self, *args):
        return self.request('projects', *args)


class Cluster(object):
    def __init__(self, ironworker, cluster_id, jwt):
        self.ironworker = ironworker
        self.cluster_id = cluster_id
        self.jwt = jwt

    def get_details(self):
        return self.ironworker\
            .clusters(self.cluster_id, jwt=self.jwt).get()

    def get_stats(self):
        return self.ironworker\
            .clusters(self.cluster_id, 'stats', jwt=self.jwt).get()

    def terminate_instance(self, *instance_id):
        return self.ironworker\
            .clusters(self.cluster_id, 'terminate', jwt=self.jwt)\
            .set_params(instance_ids=instance_id).post()

    def terminate_instance_cleanup(self, *instance_id):
        return self.ironworker\
            .clusters(self.cluster_id, 'cleanup_terminated', jwt=self.jwt)\
            .set_params(instance_ids=instance_id).post()

    def share(self, email):
        return self.ironworker\
            .clusters(self.cluster_id, 'share', jwt=self.jwt)\
            .set_params(email=email).post()


class ClusterStats(object):
    def __init__(self, cluster_stats):
        self.stats = cluster_stats

    @property
    def num_instances(self):
        return len([i for i in self.stats['instances']
                    if 'terminate' != i.get('type', '').lower()])

    def find_machine(self, filter_callback, find_all=False):
        ms = []
        for m in self.stats['instances']:
            if filter_callback(m):
                if not find_all:
                    return m
                else:
                    ms.append(m)
        else:
            if not find_all:
                raise Exception('Machine not found')
        return ms

    def get_idle_instances(self, **kwargs):
        return self.find_machine(
            lambda m: m['runners_available'] == m['runners_total'], **kwargs)


class Project(object):
    def __init__(self, ironworker, project_id):
        self.ironworker = ironworker
        self.project_id = project_id

    def list_codes(self, **q):
        return self.ironworker\
            .projects(self.project_id, 'codes').set_query(**q).get()

    def get_code_details(self, code_id):
        return self.ironworker\
            .projects(self.project_id, 'codes', code_id).get()

    def delete_code(self, code_id):
        return self.ironworker\
            .projects(self.project_id, 'codes', code_id).delete()

    def download_code(self, code_id):
        return self.ironworker\
            .projects(self.project_id, 'codes', code_id, 'download').get()

    def list_code_revisions(self, code_id, **q):
        return self.ironworker\
            .projects(self.project_id, 'codes', code_id, 'revisions')\
            .set_query(**q).get()

    def list_code_stats(self, code_id, **q):
        return self.ironworker\
            .projects(self.project_id, 'codes', code_id, 'stats')\
            .set_query(**q).get()

    def upload_code(self, data, archive_file=None):
        req = self.ironworker.projects(self.project_id, 'codes')\
            .add_field('data', json.dumps(data))
        print(req.set_method('post'))
        if archive_file is not None:
            f = open(archive_file, 'rb')
            req.add_file('file', 'file.zip', f, 'application/zip')
        else:
            f = None
        try:
            return req.post()
        finally:
            if f is not None:
                f.close()

    def queue_task(self, code_name, payload, **data):
        data['code_name'] = code_name
        data['payload'] = payload
        return self.ironworker\
            .projects(self.project_id, 'tasks')\
            .set_params(tasks=[data]).post()

    def get_task_details(self, task_id):
        return self.ironworker\
            .projects(self.project_id, 'tasks', task_id).get()

    def list_tasks(self, **q):
        return self.ironworker\
            .projects(self.project_id, 'tasks').set_query(**q).get()

    def get_task_log(self, task_id):
        return self.ironworker\
            .projects(self.project_id, 'tasks', task_id, 'log').get()

    def cancel_task(self, task_id):
        return self.ironworker\
            .projects(self.project_id, 'tasks', task_id, 'cancel').post()


def encrypt_payload(pub_key_str, payload):
    pub = load_pem_public_key(pub_key_str, backend=new_backend())
    secret = aead.AESGCM.generate_key(AES_BITS)
    encrypted_secret = pub.encrypt(
        secret,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )
    nonce = os.urandom(GCM_NONCE_LENGTH)
    encrypted_message = aead.AESGCM(secret).encrypt(nonce, payload, None)
    ctext = bytearray(encrypted_secret) + bytearray(encrypted_message) + \
            bytearray(nonce)
    payload = b64encode(ctext)
    return payload


if '__main__' == __name__:
    def main():
        import argparse

        args = argparse.ArgumentParser()

        # request actions
        args.add_argument('-c', dest='config', default='iron.json')
        args.add_argument('-m', dest='method', default='get')
        args.add_argument('-v', dest='verbose', action='store_true')
        args.add_argument('--encrypt', dest='encrypt')
        args.add_argument('--data', dest='data', default='')
        args.add_argument('--multipart', dest='multipart', action='store_true')
        args.add_argument('--cluster', dest='cluster_id', default=None)
        args.add_argument('--project', dest='project_id', action='store_true')

        # project actions
        args.add_argument('--task', dest='task', action='store_true')
        args.add_argument(
                '--task-name', dest='task_name', default=None)
        args.add_argument(
                '--task-config', dest='task_config', default='task.json')
        args.add_argument(
                '--task-ignore', dest='ignore_file', default='.gitignore')
        args.add_argument(
                '--task-source', dest='source_dir')
        args.add_argument(
                '--task-upload', dest='upload', action='store_true')
        args.add_argument(
                '--task-execute', dest='execute', action='store_true')
        args.add_argument(
                '--task-payload', dest='payload', default='')
        args.add_argument(
                '--task-wait', dest='wait', action='store_true')

        args.add_argument('url', nargs='?', default='')
        args = args.parse_args()

        with open(os.path.join(os.getcwd(), args.config)) as f:
            config = json.loads(f.read())

        iw = IronWorker(config['token'])

        if args.task:
            run_project_request(args, config, iw)
        else:
            run_request(args, config, iw)

    def run_request(args, config, iw):
        if args.project_id:
            req = iw.projects(config['project_id'], args.url)
        elif args.cluster_id:
            cluster_token = config['clusters'][args.cluster_id]
            req = iw.clusters(args.cluster_id, args.url, jwt=cluster_token)
        else:
            req = iw.request(args.url)
            if args.url.startswith('clusters'):
                req.set_query(jwt=config['clusters'].values()[0])

        if args.data:
            print(args.data)
            data = json.loads(args.data)
            if args.multipart:
                for k, v in data.items():
                    print(k, v)
                    req.add_field(str(k), str(v))
            else:
                req.set_params(**data)

        method = args.method.lower()
        req.set_method(method)

        if args.verbose:
            sys.stderr.write(str(req) + '\n')

        res = getattr(req, method)()
        if not res.has_error:
            if res.is_json:
                print(json.dumps(res.data, indent=4))
            else:
                print(res.text)
        else:
            print(res.text)

    def run_project_request(args, config, iw):
        project_id = config['project_id']
        token = config['token']
        config_file = os.path.join(os.getcwd(), args.task_config)

        iw = IronWorker(token)
        proj = Project(iw, project_id)
        with open(config_file) as f:
            task_config = json.loads(f.read())
            if args.task_name:
                task_config['name'] = args.task_name

        if args.upload:
            source_dir = os.path.join(os.getcwd(), args.source_dir)
            ignore_file = os.path.join(os.getcwd(), args.ignore_file)
            ignore_files = ziputil.parse_ignore_file(ignore_file)
            archive_file = os.path.join(
                '/tmp', '.'.join([str(uuid4()), 'zip']))
            ziputil.zip_dir(source_dir, archive_file, ignore_files)

            try:
                res = proj.upload_code(task_config, archive_file)
                print(res.text)
            finally:
                os.unlink(archive_file)

        if args.execute:
            encrypt_name = args.encrypt or task_config.get('encrypt', False)
            if encrypt_name:
                if args.encrypt:
                    pkfile = os.path.join(os.getcwd(), encrypt_name)
                else:
                    pkfile = os.path.join(os.path.dirname(config_file),
                                          encrypt_name)
                with open(pkfile) as f:
                    args.payload = encrypt_payload(f.read(), args.payload)
                if args.verbose:
                    sys.stderr.write(args.payload + '\n')
            res = proj.queue_task(
                code_name=task_config['name'],
                payload=args.payload,
                **task_config)
            print(res.text)
            task_id = res.data.get('tasks')[0].get('id')

            if args.wait:
                while True:
                    res = proj.get_task_details(task_id)
                    status = res.data.get('status')
                    if 'complete' == status:
                        break
                    else:
                        print(res.data['code_name'], status)
                    time.sleep(1)

                res = proj.get_task_log(task_id)
                print(res.text)

    main()
