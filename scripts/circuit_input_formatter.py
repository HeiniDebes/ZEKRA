#!/usr/bin/python3
#################################
## Author: Heini Bergsson Debes
#################################
# Purpose is to:
# (1) encode the adjacency list (optionally padded)
# (2) get the hash of the encoded adjacency list, translator, and recorded execution path (after padding)
# (3) format inputs for ZEKRA circuit

import sys, getopt, math
from poseidon.poseidon_hash import poseidon_hash, p

P_BITWIDTH=len(format(p,'0b'))
EMPTY_DEST_ADDR=0
JUMPKIND_BITWIDTH=2
LABEL_BITWIDTH=None
BUCKET_BITWIDTH=None
ADDR_BITWIDTH=None
ADJLIST_LEVELS=None
ADJLIST_FILENAME='adjlist'
NUMIFIED_ADJLIST_FILENAME='numified_adjlist'
NUMIFIED_PATH_FILENAME='numified_path'
RECORDED_PATH_FILENAME='recorded_path'
TRANSLATOR_FILENAME='translator'
PAD_ADJLIST=None
PAD_PATH=None

def format_adjlist(adjlist, delim=' '):
    tmp = {}
    for node in adjlist:
        neighbors = node.split(' ')
        node = neighbors[0]
        neighbors = neighbors[1:]
        tmp[node] = neighbors
    return tmp

def encode_adjlist(adjlist):
    encoded_adjlist = [] # list of tuples (node, {bucket-rems levels})
    for node in adjlist:
        levels = {} # dictionary of bucket-rems pairs: {'bucket1':'rems1', 'bucket2':'rems2'}
        for neighbor in adjlist[node]: # dividend = divisor * quotient + remainder
            neighbor = int(neighbor)
            bucket = int(neighbor / 8) # quotient
            rem = neighbor % 8 # remainder
            if bucket not in levels:
                levels[bucket] = 0
            levels[bucket] |= (1 << rem) # set bit
        encoded_adjlist.append((node, levels))
    return encoded_adjlist

def read_adjlist(adjlist_file, pad_adjlist=None):
    adjlist = []
    len_without_pad = 0
    with open(adjlist_file, 'r') as file_in:
        for line in file_in.readlines():
            node = line.rstrip()
            adjlist.append(node)
    len_without_pad = len(adjlist)
    if pad_adjlist:
        if pad_adjlist<len(adjlist):
            raise Exception('Adjacency list contains %s nodes. Cannot apply padding of %s nodes.'%(len(adjlist), pad_adjlist))
        # append nodes with no neighbors to adjacency list
        while len(adjlist)<pad_adjlist:
            fantom_node = str(len(adjlist))
            adjlist.append(fantom_node)
    return adjlist, len_without_pad

def read_translator(translator_file, pad_translator):
    translator=[]
    len_without_pad = 0
    with open(translator_file, 'r') as file_in:
        for hex_addr in file_in.readlines():
            hex_addr=hex_addr.rstrip()
            translator.append(int(hex_addr,16))
    len_without_pad = len(translator)
    if pad_translator:
        if pad_translator<len(translator):
            raise Exception('Translator contains %s entries. Cannot apply padding of %s entries.'%(len(translator), pad_translator))
        # append empty entries to translator
        translator.extend([0]*(pad_translator-len(translator)))
    # append one extra entry to allow for translation of empty destination addresses
    translator.append(EMPTY_DEST_ADDR)
    return translator, len_without_pad

def read_path(path_file, pad_path, empty_move_dst):
    transitions = []
    initial_node = None
    final_node = None
    len_without_pad = 0
    with open(path_file, 'r') as file_in: # don't include the starting node (it is already assumed in the circuit)
        initial_node, final_node = [node.split('=')[1] for node in file_in.readline().rstrip().split(' ')]
        for transition in file_in.readlines():
            transition = transition.rstrip().split(' ')
            jumpkind,dst = transition[:2]
            ret = transition[2] if jumpkind=='call' else empty_move_dst
            transitions.append({
                'jumpkind':jumpkind, 
                'dst':dst, 
                'ret':ret})
    len_without_pad = len(transitions)
    if pad_path:
        if pad_path<len(transitions):
            raise Exception('Execution path contains %s transitions. Cannot apply padding of %s moves.'%(len(transitions), pad_path))
        # append empty moves to execution path
        while len(transitions)<pad_path:
            transitions.append({
                'jumpkind':'empty',
                'dst':empty_move_dst,
                'ret':empty_move_dst})
    path={'transitions':transitions,'initial_node':initial_node,'final_node':final_node,'num_transitions_pre_pad':len_without_pad}
    return path

def binify_encoded_adjlist(adjlist_encoded):
    binified = []
    for node,levels in adjlist_encoded:
        neighbors = ''
        for bucket,rems in levels.items():
            neighbors += '%s%s' %(format(rems,'08b'),format(bucket,'0%sb'%int(BUCKET_BITWIDTH)))
        if len(neighbors)==0: neighbors='0'
        binified.append((node, neighbors))
    return binified

def numify_binified_adjlist(adjlist_binified):
    return [(node, int(encoded_neighbors,2)) for node,encoded_neighbors in adjlist_binified]

def binify_path(path):
    binified = []
    for transition in path['transitions']:
        jumpkind,dst,ret = (format(0,'0%sb'%JUMPKIND_BITWIDTH),format(int(transition['dst'],16),'0%sb'%ADDR_BITWIDTH),format(0,'0%sb'%ADDR_BITWIDTH))
        if transition['jumpkind']=='call':
            jumpkind=format(1,'0%sb'%JUMPKIND_BITWIDTH)
            ret=format(int(transition['ret'],16),'0%sb'%ADDR_BITWIDTH)
        elif transition['jumpkind']=='ret':
            jumpkind=format(2,'0%sb'%JUMPKIND_BITWIDTH)
        elif transition['jumpkind']=='empty':
            jumpkind=format(3,'0%sb'%JUMPKIND_BITWIDTH)
        encoded=ret+dst+jumpkind # reverse order
        binified.append(encoded)
    return binified

def numify_binified_path(path):
    return [int(transition, 2) for transition in path]

def hash(padded_list):
    # hash first chunk
    poseidon_state=[0]*9 # empty state
    i=0
    while i<8:
        poseidon_state[i+1]=padded_list[i]
        i+=1
    poseidon_state=poseidon_hash(poseidon_state)

    # hash remaining chunks
    remaining_chunks=int(len(padded_list)/8)-1
    i=0
    while i<remaining_chunks:
        j=0
        while j<8:
            poseidon_state[j+1]=padded_list[(i+1)*8+j]+poseidon_state[j+1]
            j+=1
        poseidon_state=poseidon_hash(poseidon_state)
        i+=1
    return poseidon_state[2]

def compress(tmp_list, elem_bitwidth):
    p_bitwidth=len(format(p,'0b'))
    elems_per_field_element=math.floor(p_bitwidth/elem_bitwidth)
    compressed=[0]*math.ceil(len(tmp_list)/elems_per_field_element)

    print('\telems_per_field_element: %s (using %s-bit p)' %(elems_per_field_element,p_bitwidth))
    print('\toccupies %s field elements after compression' %len(compressed))

    i=0
    while i<len(compressed):
        j=0
        k=0
        tmp_list_idx=i*elems_per_field_element
        while j<elems_per_field_element and tmp_list_idx<len(tmp_list):
            elem=tmp_list[tmp_list_idx]
            compressed[i]=compressed[i]+(elem*2**k)
            j+=1
            k+=elem_bitwidth
            tmp_list_idx+=1
        i+=1
    return compressed

def make_multiple_of(tmp_list, factor=8, extend=0):
    padded_len=int(math.ceil(float(len(tmp_list)+extend)/factor)*factor)
    padded=tmp_list.copy()
    padded.extend([0]*(padded_len-len(tmp_list)))
    return padded

def hash_translator(translator, nonce_translator):
    print('Starting hashing of the translator')
    print('\tADDR_BITWIDTH: %s'%(ADDR_BITWIDTH))

    translator_compressed=compress(translator,ADDR_BITWIDTH)
    translator_padded=make_multiple_of(translator_compressed,8,1) # we consider poseidon with 8 inputs, so we pad the translator to make it divisible by 8 (we reserve one field element for the nonce)

    translator_padded[len(translator_padded)-1]=nonce_translator

    print('\tpadding translator with %s additional field elements (Poseidon call has arity 8 and we need to reserve 1 element for the translator nonce)' %(len(translator_padded)-len(translator_compressed)))
    print('\tcalls to Poseidon needed: %s' %math.ceil(len(translator_padded)/8))

    return hash(translator_padded)

def hash_adjlist(adjlist, levels, nonce_adjlist):
    adjlist=[encoded_neighbors for node,encoded_neighbors in adjlist]

    neighbors_bitwidth=levels*(BUCKET_BITWIDTH+8)

    print('Starting hashing of the encoded adjacency list')
    print('\tneighbors_bitwidth: %s (%s levels * (%s-bit buckets + 8-bit rems))'%(neighbors_bitwidth,levels,BUCKET_BITWIDTH))

    adjlist_compressed=compress(adjlist,neighbors_bitwidth)
    adjlist_padded=make_multiple_of(adjlist_compressed,8,1) # we consider poseidon with 8 inputs, so we pad the adjlist to make it divisible by 8 (we reserve one field element for the nonce)

    adjlist_padded[len(adjlist_padded)-1]=nonce_adjlist

    print('\tpadding compressed path with %s additional field elements (Poseidon call has arity 8 and we need to reserve 1 element for the adjacency list nonce)' %(len(adjlist_padded)-len(adjlist_compressed)))
    print('\tcalls to Poseidon needed: %s' %math.ceil(len(adjlist_padded)/8))

    return hash(adjlist_padded)

def hash_path(path, nonce_verifier, nonce_path):
    transition_bitwidth=JUMPKIND_BITWIDTH+ADDR_BITWIDTH*2

    print('Starting hashing of the execution path')
    print('\ttransition_bitwidth: %s (%s-bit jumpkind||%s-bit dest address||%s-bit ret address)'%(transition_bitwidth,JUMPKIND_BITWIDTH,ADDR_BITWIDTH,ADDR_BITWIDTH))

    path_compressed=compress(path,transition_bitwidth)
    path_padded=make_multiple_of(path_compressed,8,2) # we consider poseidon with 8 inputs, so we pad the path to make it divisible by 8 (we reserve two field elements for the two nonces)

    path_padded[len(path_padded)-2]=nonce_verifier
    path_padded[len(path_padded)-1]=nonce_path

    print('\tpadding compressed path with %s additional field elements (Poseidon call has arity 8 and we need to reserve 2 elements for the verifier and execution path nonces)' %(len(path_padded)-len(path_compressed)))
    print('\tcalls to Poseidon needed: %s' %math.ceil(len(path_padded)/8))

    return hash(path_padded)

def main(in_dir, out_dir, nonce_verifier, nonce_path, nonce_translator, nonce_adjlist):
    numified_adjlist_filename_in = in_dir+NUMIFIED_ADJLIST_FILENAME
    numified_path_filename_in    = in_dir+NUMIFIED_PATH_FILENAME
    recorded_path_filename_in    = in_dir+RECORDED_PATH_FILENAME
    translator_filename_in       = in_dir+TRANSLATOR_FILENAME

    encoded_adjlist_filename_out        = out_dir+'in_encoded_adjlist'
    translator_filename_out             = out_dir+'in_%s'%TRANSLATOR_FILENAME
    recorded_path_filename_out          = out_dir+'in_%s'%RECORDED_PATH_FILENAME
    numified_path_filename_out          = out_dir+'in_%s'%NUMIFIED_PATH_FILENAME
    initial_node_filename_out           = out_dir+'in_initial_node'
    final_node_filename_out             = out_dir+'in_final_node'
    nonce_verifier_filename_out         = out_dir+'in_nonce_verifier'
    nonce_path_filename_out             = out_dir+'in_nonce_path'
    nonce_translator_filename_out       = out_dir+'in_nonce_translator'
    nonce_adjlist_filename_out          = out_dir+'in_nonce_adjlist'
    encoded_adjlist_digest_filename_out = out_dir+'in_encoded_adjlist_digest'
    recorded_path_digest_filename_out   = out_dir+'in_%s_digest'%RECORDED_PATH_FILENAME
    translator_digest_filename_out      = out_dir+'in_%s_digest'%TRANSLATOR_FILENAME

    #############################################################
    ## Create circuit input files for the encoded adjacency list
    adjlist,len_without_pad = read_adjlist(numified_adjlist_filename_in, PAD_ADJLIST)
    adjlist = format_adjlist(adjlist)
    adjlist_encoded  = encode_adjlist(adjlist)
    adjlist_binified = binify_encoded_adjlist(adjlist_encoded)
    adjlist_numified = numify_binified_adjlist(adjlist_binified)

    output='The encoded adjacency list contains %s nodes'%len(adjlist)
    if PAD_ADJLIST: output+=' (%s without padding)'%len_without_pad
    print(output)

    with open(encoded_adjlist_filename_out, 'w') as file_out: 
        file_out.write('\n'.join(str(neighbors) for node,neighbors in adjlist_numified))
    print('Wrote encoded adjacency list to file \'%s\'' %encoded_adjlist_filename_out)

    adjlist_hash = hash_adjlist(adjlist_numified, ADJLIST_LEVELS, nonce_adjlist)

    with open(encoded_adjlist_digest_filename_out, 'w') as file_out: 
        file_out.write(str(adjlist_hash))
    print('Wrote encoded adjlist digest to file \'%s\''%encoded_adjlist_digest_filename_out)
    print('Encoded adjacency list hash: %s'%adjlist_hash)

    #############################################################
    ## Create circuit input file for translator
    translator,len_without_pad=read_translator(translator_filename_in, PAD_ADJLIST) # the size should follow that of the adjacency list

    output='The translator contains %s addresses'%len(translator)
    if PAD_ADJLIST: output+=' (%s without padding)'%len_without_pad
    print(output)

    with open(translator_filename_out, 'w') as file_out: 
        file_out.write('\n'.join(str(addr) for addr in translator))
    print('Wrote translator to file \'%s\'' %translator_filename_out)

    translator_hash=hash_translator(translator, nonce_translator)

    with open(translator_digest_filename_out, 'w') as file_out: 
        file_out.write(str(translator_hash))
    print('Wrote translator digest to file \'%s\''%translator_digest_filename_out)
    print('Translator hash: %s'%translator_hash)

    #############################################################
    ## Create circuit input files for the numified execution path
    numified_path=read_path(numified_path_filename_in, PAD_PATH, len(adjlist))

    output='The numified execution path contains %s transitions'%len(numified_path['transitions'])
    if PAD_PATH: output+=' (%s without padding)'%numified_path['num_transitions_pre_pad']
    print(output)

    with open(numified_path_filename_out, 'w') as file_out: 
        output=''
        for transition in numified_path['transitions']: 
            output+='%s %s\n'%(transition['dst'],transition['ret'])
        file_out.write(output.rstrip())
    print('Wrote numified execution path to file \'%s\'' %numified_path_filename_out)

    with open(initial_node_filename_out, 'w') as file_out: 
        file_out.write(numified_path['initial_node'])
    print('Wrote initial node = %s to file \'%s\''%(numified_path['initial_node'],initial_node_filename_out))
    with open(final_node_filename_out, 'w') as file_out: 
        file_out.write(numified_path['final_node'])
    print('Wrote final node = %s to file \'%s\''%(numified_path['final_node'],final_node_filename_out))

    #############################################################
    ## Create circuit input files for the nonces
    with open(nonce_verifier_filename_out, 'w') as file_out: 
        file_out.write(str(nonce_verifier))
    print('Wrote verifier\'s nonce to file \'%s\''%nonce_verifier_filename_out)
    with open(nonce_path_filename_out, 'w') as file_out: 
        file_out.write(str(nonce_path))
    print('Wrote execution path\'s nonce to file \'%s\''%nonce_path_filename_out)
    with open(nonce_translator_filename_out, 'w') as file_out: 
        file_out.write(str(nonce_translator))
    print('Wrote translator\'s nonce to file \'%s\''%nonce_translator_filename_out)
    with open(nonce_adjlist_filename_out, 'w') as file_out: 
        file_out.write(str(nonce_adjlist))
    print('Wrote adjacency list\'s nonce to file \'%s\''%nonce_adjlist_filename_out)

    #############################################################
    ## Create circuit input files for the recorded execution path
    recorded_path=read_path(recorded_path_filename_in, PAD_PATH, str(hex(EMPTY_DEST_ADDR)))

    output='The recorded execution path contains %s transitions'%len(recorded_path['transitions'])
    if PAD_PATH: output+=' (%s without padding)'%recorded_path['num_transitions_pre_pad']
    print(output)

    with open(recorded_path_filename_out, 'w') as file_out: 
        output=''
        for transition in recorded_path['transitions']:
            jumpkind=transition['jumpkind']
            if jumpkind=='jump':jumpkind=0
            elif jumpkind=='call':jumpkind=1
            elif jumpkind=='ret':jumpkind=2
            elif jumpkind=='empty':jumpkind=3
            output+='%s %s %s\n'%(jumpkind,int(transition['dst'],16),int(transition['ret'],16))
        file_out.write(output.rstrip())
    print('Wrote recorded execution path to file \'%s\'' %recorded_path_filename_out)

    recorded_path_binified = binify_path(recorded_path)
    recorded_path_numified = numify_binified_path(recorded_path_binified)
    recorded_path_hash = hash_path(recorded_path_numified, nonce_verifier, nonce_path)

    with open(recorded_path_digest_filename_out, 'w') as file_out: 
        file_out.write(str(recorded_path_hash))
    print('Wrote recorded execution path digest to file \'%s\''%recorded_path_digest_filename_out)
    print('Recorded execution path hash: %s'%recorded_path_hash)

def get_min_adjlist_levels(in_dir):
    numified_adjlist_filename_in=in_dir+NUMIFIED_ADJLIST_FILENAME
    adjlist,len_without_pad = read_adjlist(numified_adjlist_filename_in,PAD_ADJLIST)
    adjlist = format_adjlist(adjlist)
    encoded_adjlist = encode_adjlist(adjlist)
    levels_required = len(max([list(levels) for node,levels in encoded_adjlist], key=len))
    return levels_required

def get_min_label_bitwidth(in_dir):
    numified_adjlist_filename_in=in_dir+NUMIFIED_ADJLIST_FILENAME
    adjlist,len_without_pad=read_adjlist(numified_adjlist_filename_in,PAD_ADJLIST)
    max_label=len(adjlist)
    bitwidth=len(format(max_label,'0b'))
    print('The input adjacency list contains %s entries/nodes (i.e., max label is %s, which occupies %s bits)' %(len(adjlist),max_label,bitwidth))
    return bitwidth

def get_min_bucket_bitwidth(in_dir):
    numified_adjlist_filename_in=in_dir+NUMIFIED_ADJLIST_FILENAME
    adjlist,len_without_pad=read_adjlist(numified_adjlist_filename_in,PAD_ADJLIST)
    max_label=len(adjlist) # the final label is used as the empty label
    max_bucket=math.floor(max_label/8)
    max_bucket_bitwidth=len(format(max_bucket,'0b'))
    return max_bucket_bitwidth

def get_min_addr_bitwidth(in_dir):
    adjlist_filename_in=in_dir+ADJLIST_FILENAME
    adjlist,len_without_pad=read_adjlist(adjlist_filename_in,PAD_ADJLIST)
    max_address=0
    for entry in adjlist:
        addresses=entry.split(' ')
        for address in addresses:
            val=int(address,16)
            if val>max_address:
                max_address=val
    bitwidth=len(format(max_address,'0b'))
    print('The maximum address in the input adjacency list is %s and occupies %s bits' %(hex(max_address),bitwidth))
    return bitwidth

def usage():
    print('Usage: %s -a <dir> [options]'%sys.argv[0])
    print('Options:')
    print('  -h                       This help message')
    print('  -a <dir>                 Path to specific target application\'s directory containing the \'adjlist\', \'numified_adjlist\', \'translator\', \'recorded_path\', and \'numified_path\' files')
    print('  --pad-adjlist-to <len>   Pad the adjlist and translator with zeros (empty entries) until their length is <len> (default is to not pad)')
    print('  --pad-path-to <len>      Pad the execution path with zeros (empty moves) until its length is <len> (default is to not pad)')
    print('  --adjlist-levels <num>   Use <num> levels (pairs of bucket-rems) for encoding the adjacency list. Note that this primarily affects the adjacency list compression which is done prior to hashing to reduce the number of calls to Poseidon (default is to use the minimum levels necessary to maximize compression and minimize the size of the generated circuit)')
    print('  --output-dir <dir>       Store the circuit input files in <dir> (default is to store the files in the same directory as the targeted application)')
    print('  --nonce-verifier <num>   Verifier\'s nonce to hash with the execution path (default 0)')
    print('  --nonce-path <num>       Blinding factor (nonce) to hash with the execution path (default 0)')
    print('  --nonce-translator <num> Blinding factor (nonce) to hash with the address-to-label translator (default 0)')
    print('  --nonce-adjlist <num>    Blinding factor (nonce) to hash with the encoded adjacency list (default 0)')
    print('  --label-bitwidth <num>   Use <num> bits to represent each numified destination address when compressing/hashing the numified execution path (default is to use the minimum number of bits as determined by the size of the adjacency list).')
    print('  --bucket-bitwidth <num>  Use <num> bits to represent each quotient (bucket) in the adjacency list encoding (default is to use the miminum number of bits as determined by the length of the adjacency list).')
    print('  --address-bitwidth <num> Use <num> bits to represent each destination address when compressing/hashing the raw/recorded execution path (default is to use the minimum number of bits as determined by the recorded execution path provided as input).')

if __name__ == '__main__':
    in_dir  = None
    out_dir = None
    nonce_verifier   = 0
    nonce_path       = 0
    nonce_translator = 0
    nonce_adjlist    = 0
    try:
        opts,args=getopt.getopt(sys.argv[1:],'ha:',['pad-adjlist-to=','pad-path-to=','adjlist-levels=','output-dir=','nonce-verifier=','nonce-path=','nonce-translator=','nonce-adjlist=','label-bitwidth=','bucket-bitwidth=','address-bitwidth='])
    except getopt.GetoptError as err:
        print(err)
        usage()
        sys.exit(2)
    for opt,arg in opts:
        if opt=='-h':
            usage()
            sys.exit()
        elif opt=='-a':
            if not arg.endswith('/'): arg=arg+'/'
            in_dir=arg
        elif opt=='--pad-adjlist-to':
            PAD_ADJLIST=int(arg)
        elif opt=='--pad-path-to':
            PAD_PATH=int(arg)
        elif opt=='--adjlist-levels':
            ADJLIST_LEVELS=int(arg)
        elif opt=='--output-dir':
            if not arg.endswith('/'): arg=arg+'/'
            out_dir=arg
        elif opt=='--nonce-verifier':
            nonce_verifier=int(arg)
            if len(format(nonce_verifier,'0b'))>=P_BITWIDTH:
                print('%s: the provided verifier nonce is too big. Maximum bitwidth is %s due to the currently considered finite field.'%(sys.argv[0],P_BITWIDTH))
                usage()
                sys.exit()
        elif opt=='--nonce-path':
            nonce_path=int(arg)
            if len(format(nonce_path,'0b'))>=P_BITWIDTH:
                print('%s: the provided execution path nonce is too big. Maximum bitwidth is %s due to the currently considered finite field.'%(sys.argv[0],P_BITWIDTH))
                usage()
                sys.exit()
        elif opt=='--nonce-translator':
            nonce_translator=int(arg)
            if len(format(nonce_translator,'0b'))>=P_BITWIDTH:
                print('%s: the provided translator nonce is too big. Maximum bitwidth is %s due to the currently considered finite field.'%(sys.argv[0],P_BITWIDTH))
                usage()
                sys.exit()
        elif opt=='--nonce-adjlist':
            nonce_adjlist=int(arg)
            if len(format(nonce_adjlist,'0b'))>=P_BITWIDTH:
                print('%s: the provided adjacency list nonce is too big. Maximum bitwidth is %s due to the currently considered finite field.'%(sys.argv[0],P_BITWIDTH))
                usage()
                sys.exit()
        elif opt=='--label-bitwidth':
            LABEL_BITWIDTH=int(arg)
        elif opt=='--bucket-bitwidth':
            BUCKET_BITWIDTH=int(arg)
        elif opt=='--address-bitwidth':
            ADDR_BITWIDTH=int(arg)
    if not in_dir:
        print('%s: fatal error: no application input directory specified \n'%sys.argv[0])
        usage()
        sys.exit()

    min_adjlist_levels=get_min_adjlist_levels(in_dir)
    if not ADJLIST_LEVELS: 
        ADJLIST_LEVELS=min_adjlist_levels
    else:
        if min_adjlist_levels>ADJLIST_LEVELS:
            print('%s: the encoded adjacency list requires minimum %s levels.'%(sys.argv[0],min_adjlist_levels))
            usage()
            sys.exit()
    min_label_bitwidth=get_min_label_bitwidth(in_dir)
    if not LABEL_BITWIDTH: 
        LABEL_BITWIDTH=min_label_bitwidth
    else:
        if min_label_bitwidth>LABEL_BITWIDTH:
            print('%s: the provided label bitwidth is too small. Minimum bitwidth is %s.'%(sys.argv[0],min_label_bitwidth))
            usage()
            sys.exit()
    min_bucket_bitwidth=get_min_bucket_bitwidth(in_dir)
    if not BUCKET_BITWIDTH:
        BUCKET_BITWIDTH=min_bucket_bitwidth
    else:
        if min_bucket_bitwidth>BUCKET_BITWIDTH:
            print('%s: the provided bucket bitwidth is too small. Minimum bitwidth is %s.'%(sys.argv[0],min_bucket_bitwidth))
            usage()
            sys.exit()
    min_addr_bitwidth=get_min_addr_bitwidth(in_dir)
    if not ADDR_BITWIDTH:
        ADDR_BITWIDTH=min_addr_bitwidth
    else:
        if min_addr_bitwidth>ADDR_BITWIDTH:
            print('%s: the provided address bitwidth is too small. Minimum bitwidth is %s.'%(sys.argv[0],min_addr_bitwidth))
            usage()
            sys.exit()
    encoded_neighbors_bitwidth=(BUCKET_BITWIDTH+8)*ADJLIST_LEVELS
    if encoded_neighbors_bitwidth>=P_BITWIDTH:
        print('%s: (BUCKET_BITWIDTH+8)*ADJ_LIST_LEVELS is %s which exceeds p\'s bitwidth of %s bits (see the implementation notes)'%(sys.argv[0],encoded_neighbors_bitwidth,P_BITWIDTH))
        usage()
        sys.exit()
    if not out_dir:
        out_dir=in_dir

    print('Minimum:     ADJLIST_LEVELS=%s LABEL_BITWIDTH=%s BUCKET_BITWIDTH=%s ADDR_BITWIDTH=%s' %(min_adjlist_levels,min_label_bitwidth,min_bucket_bitwidth,min_addr_bitwidth))
    print('Considering: ADJLIST_LEVELS=%s LABEL_BITWIDTH=%s BUCKET_BITWIDTH=%s ADDR_BITWIDTH=%s\n' %(ADJLIST_LEVELS,LABEL_BITWIDTH,BUCKET_BITWIDTH,ADDR_BITWIDTH))

    main(in_dir, out_dir, nonce_verifier, nonce_path, nonce_translator, nonce_adjlist)
