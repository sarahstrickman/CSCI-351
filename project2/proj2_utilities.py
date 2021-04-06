"""
utilities that will be used by the router_process
"""


MAX_BUFFER_SIZE = 65536

LOCAL = "127.0.0.1"
QUEEG = "129.21.30.37"
COMET = "129.21.34.80"
RHEA = "129.21.37.49"
GLADOS = "129.21.22.196"


def print_routing_table(hostname, table):
    st = "ROUTING TABLE FOR " + hostname + "\n"
    st += "DEST\t\tMASK\t\tCOST\tNEXT_HOP\n"
    for k in table.keys():
        v = table[k]
        st = st + str(k) + "\t"
        st = st + str(v[0]) + "\t"
        st = st + str(v[1]) + "\t"
        st = st + str(v[2]) + "\n"
    print(st)


def get_mask(addr):
    """
    this would have more stuff in it if the masks for the given hosts were different
    (I got this info from the project doc).

    :param addr: IP address
    :return: 255.255.255.0
    """
    return "255.255.255.0"


def get_neighbors(hostname):
    if hostname == "QUEEG" or hostname == QUEEG:
        return [COMET, GLADOS]
    elif hostname == "COMET" or hostname == COMET:
        return [QUEEG, RHEA]
    elif hostname == "RHEA" or hostname == RHEA:
        return [COMET, GLADOS]
    elif hostname == "GLADOS" or hostname == GLADOS:
        return [QUEEG, RHEA]
    else:
        return [LOCAL]  # loopback if you are not in the network ring described in the proj2 document


def get_costs(hostname):
    if hostname == "QUEEG" or hostname == QUEEG:
        return 1
    elif hostname == "COMET" or hostname == COMET:
        return 3
    elif hostname == "RHEA" or hostname == RHEA:
        return 2
    elif hostname == "GLADOS" or hostname == GLADOS:
        return 4
    else:
        return 5  # loopback if you are not in the network ring described in the proj2 document