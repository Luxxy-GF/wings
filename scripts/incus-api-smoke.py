#!/usr/bin/env python3
"""Real Incus 7.0 LTS REST checks using only newly created, tagged test resources."""
import argparse
import http.client
import json
import socket
import uuid
from urllib.parse import quote, urlencode


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__('localhost', timeout=120)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


class API:
    def __init__(self, path):
        self.path = path

    def request(self, method, path, project='default', body=None, headers=None, raw=False):
        connection = UnixHTTP(self.path)
        separator = '&' if '?' in path else '?'
        path += separator + urlencode({'project': project})
        headers = dict(headers or {})
        if body is not None and not isinstance(body, bytes):
            body = json.dumps(body).encode()
            headers['Content-Type'] = 'application/json'
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            status, etag = response.status, response.getheader('ETag')
            content = response.read()
            return status, etag, content if raw else json.loads(content)
        finally:
            connection.close()

    def success(self, method, path, project='default', body=None, headers=None):
        status, etag, result = self.request(method, path, project, body, headers)
        if not 200 <= status < 300:
            raise RuntimeError(f'{method} {path}: HTTP {status}: {result.get("error", "unknown error")}')
        if result.get('type') == 'async':
            status, _, result = self.request('GET', result['operation'] + '/wait?timeout=120', project)
            if status != 200 or result['metadata'].get('status_code') != 200:
                raise RuntimeError(f'Incus operation failed: {result.get("metadata", {}).get("err", result.get("error"))}')
        return result.get('metadata'), etag


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket', default='/var/lib/incus/unix.socket')
    parser.add_argument('--pool', required=True, help='Existing disposable-node pool; never formatted or deleted')
    parser.add_argument('--listen-ip', required=True)
    parser.add_argument('--bridge-cidr', default='10.238.25.1/24')
    args = parser.parse_args()
    api = API(args.socket)
    info, _ = api.success('GET', '/1.0')
    version = info['environment']['server_version']
    release = tuple(int(part) for part in version.split('-')[0].split('.'))
    assert release[:2] == (7, 0) and release >= (7, 0, 1), version
    required = {'instance_oci', 'instance_oci_entrypoint', 'oci_network_config', 'network_forward', 'file_storage_volume'}
    assert required <= set(info['api_extensions']), 'Required API extension missing'
    pool, _ = api.success('GET', '/1.0/storage-pools/' + quote(args.pool, safe=''))
    assert pool['driver'] in ('btrfs', 'zfs'), 'Native-quota test requires btrfs or ZFS'
    print(f'PASS daemon version/capabilities: {version}', flush=True)
    identity = uuid.uuid4().hex
    project = 'wings-api-' + identity
    network = 'wga' + identity[:8]
    volume = 'wgc-api-' + identity[:8]
    owner = 'wings-api:' + identity
    cleanup = []
    failure = None
    try:
        api.success('POST', '/1.0/projects', body={'name': project, 'config': {'features.images': 'true', 'features.profiles': 'true', 'features.storage.volumes': 'true', 'features.networks': 'false', 'user.wings.owner': owner}})
        cleanup.append(('DELETE', '/1.0/projects/' + project, 'default'))
        api.success('POST', '/1.0/networks', body={'name': network, 'type': 'bridge', 'config': {'ipv4.address': args.bridge_cidr, 'ipv4.nat': 'true', 'ipv4.dhcp': 'true', 'ipv6.address': 'none', 'user.wings.owner': owner}})
        cleanup.append(('DELETE', '/1.0/networks/' + network, 'default'))
        forwards = '/1.0/networks/' + network + '/forwards'
        path = forwards + '/' + quote(args.listen_ip, safe='')
        # Derive a usable private target from the caller's dedicated test subnet.
        import ipaddress
        subnet = ipaddress.ip_interface(args.bridge_cidr).network
        target = str(subnet.network_address + 2)
        ports = [{'protocol': protocol, 'listen_port': '35401', 'target_port': '35401', 'target_address': target, 'description': owner + ':first'} for protocol in ('tcp', 'udp')]
        api.success('POST', forwards, body={'listen_address': args.listen_ip, 'description': owner, 'config': {}, 'ports': ports})
        cleanup.append(('DELETE', path, 'default'))
        forward, old_etag = api.success('GET', path)
        assert len(forward['ports']) == 2
        more = {'protocol': 'tcp', 'listen_port': '35402', 'target_port': '35402', 'target_address': target, 'description': owner + ':second'}
        forward['ports'].append(more)
        writable = {key: forward[key] for key in ('description', 'config', 'ports')}
        api.success('PUT', path, body=writable, headers={'If-Match': old_etag})
        status, _, _ = api.request('PUT', path, body=writable, headers={'If-Match': old_etag})
        # Incus 7.0.1 exposes an ETag but ForwardUpdate does not enforce If-Match.
        assert status == 200, f'Unexpected Incus 7.0 forward update behavior: {status}'
        status, _, error = api.request('PUT', path, body={'description': owner, 'config': {}, 'ports': ports + [ports[0]]})
        assert status in (400, 500) and 'listen port' in error.get('error', '').lower(), f'Duplicate protocol/port must fail validation: {status}: {error}'
        outside = dict(more, target_address='192.0.2.254')
        status, _, error = api.request('PUT', path, body={'description': owner, 'config': {}, 'ports': ports + [outside]})
        assert status in (400, 500) and 'subnet' in error.get('error', '').lower(), f'Target outside bridge subnet must fail validation: {status}: {error}'
        forward, _ = api.success('GET', path)
        assert len(forward['ports']) == 3, 'Failed updates changed existing forwarding'
        print('PASS bridge/forward CRUD, shared-IP entries, and collision/subnet rejection; If-Match is not enforced by Incus 7.0.1', flush=True)
        volume_path = '/1.0/storage-pools/' + quote(args.pool, safe='') + '/volumes/custom/' + volume
        api.success('POST', '/1.0/storage-pools/' + quote(args.pool, safe='') + '/volumes/custom', project, {'name': volume, 'type': 'custom', 'content_type': 'filesystem', 'config': {'size': '16MiB', 'security.shifted': 'true', 'user.wings.owner': owner}})
        cleanup.append(('DELETE', volume_path, project))
        files = volume_path + '/files?path=%2Fprobe'
        status, _, _ = api.request('POST', files, project, b'control-volume-test', {'X-Incus-type': 'file', 'X-Incus-mode': '0600', 'X-Incus-uid': '1000', 'X-Incus-gid': '1000'})
        assert status == 200, f'Custom-volume file write failed: {status}'
        status, _, content = api.request('GET', files, project, raw=True)
        assert status == 200 and content == b'control-volume-test'
        volume_info, _ = api.success('GET', volume_path, project)
        assert volume_info['config']['size'] == '16MiB' and volume_info.get('used_by', []) == []
        print('PASS shifted custom-volume files while unattached and quota configuration', flush=True)
    except BaseException as error:
        failure = error
    finally:
        errors = []
        for method, path, scope in reversed(cleanup):
            try:
                api.success(method, path, scope)
            except Exception as error:
                errors.append(str(error))
        if errors:
            print('Cleanup errors: ' + '; '.join(errors), flush=True)
            if failure is None:
                failure = RuntimeError('Owned test resources were not fully removed')
    if failure:
        raise failure
    print('PASS owned-resource cleanup; supplied storage pool retained', flush=True)


if __name__ == '__main__':
    main()
