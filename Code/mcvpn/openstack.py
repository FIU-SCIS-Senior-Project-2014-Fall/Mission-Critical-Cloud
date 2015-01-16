import novaclient.v1_1.client as nvclient
from credentials import get_nova_creds

class Openstack(object):
    '''
    Class responsible for managing connection to Openstack
    '''
    def nova_connect(self):
        creds = get_nova_creds()
        nova = nvclient.Client(**creds)
        return nova

    def list_vms(self):
        nova = self.nova_connect()
        retrun nova.servers.list()
