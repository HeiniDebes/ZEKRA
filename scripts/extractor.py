#!/usr/bin/python3
#################################
## Author: Heini Bergsson Debes
#################################
# Purpose is to extract:
# (1) numified adjacency list (CFG),
# (2) label translator (raw node label -> numified label),
# (3) example execution path (with node/BBL labels already converted into the corresponsing numified version)

import os, re, sys, getopt
import subprocess
import angr
import networkx as nx
import statistics
import logging
from angr.knowledge_plugins.cfg import CFGNode
from circuit_input_formatter import format_adjlist, encode_adjlist

def compile(c_filenames, out_file):
    cmd = ['gcc', '-o', out_file]
    cmd.extend(c_filenames)
    cmd.extend(['-Os', '-g0', '-lm', '-fno-optimize-sibling-calls'])
    print(' '.join(cmd))
    subprocess.run(cmd, check=True)

def get_cfg(proj):
    cfg = proj.analyses.CFGFast(normalize=True, show_progressbar=True, resolve_indirect_jumps=True)
    return cfg

def get_execution_path(proj, cfg):
    initial_state = proj.factory.entry_state()
    simgr = proj.factory.simgr(initial_state)
    transitions  = []
    initial_node = 0
    final_node   = 0
    end_state    = None
    try:
        first_step = True
        while True:
            simgr.step()
            if first_step:
                initial_node=list(simgr.active[0].history.recent_bbl_addrs)[-1]
                first_step=False
            if len(simgr.active)==1:
                jumpkind=list(simgr.active[0].history.jumpkinds)[-1]
                if jumpkind=='Ijk_Call':
                    transitions.append({
                        'jumpkind':'call', 
                        'dst':simgr.active[0].history.jump_target._model_concrete.value, 
                        'ret':simgr.active[0].callstack.ret_addr})
                elif jumpkind=='Ijk_Ret':
                    transitions.append({
                        'jumpkind':'ret', 
                        'dst':simgr.active[0].history.jump_target._model_concrete.value, 
                        'ret':None})
                elif jumpkind=='Ijk_Boring':
                    transitions.append({
                        'jumpkind':'jump', 
                        'dst':simgr.active[0].history.jump_target._model_concrete.value, 
                        'ret':None})
                elif jumpkind=='Ijk_Exit':
                    end_state='reached an exit'
                    break
                else:
                    print("[-] Encountered currently unsupported jumpkind = %s in execution path" %jumpkind)
                    exit(1)
            else:
                if len(simgr.deadended)==1: end_state='done'
                elif len(simgr.errored)==1: end_state='the error \'%s\' was raised' %simgr.errored[0].error
                else: end_state='something happened'
                break
    except Exception as e:
        print(e)
        exit(1)

    # add missing nodes and edges
    state=initial_node
    for transition in transitions:
        if transition['jumpkind']=='call':
            if len(cfg.get_all_nodes(transition['ret']))==0: # return node does not exist in the current CFG
                node=CFGNode(transition['ret'], 0, cfg)
                cfg.graph.add_node(node) # just add it to the CFG
        if len(cfg.get_all_nodes(transition['dst']))==0: # destination node does not exist in the current CFG
            node=CFGNode(transition['dst'], 0, cfg)
            cfg.graph.add_node(node) # just add it to the CFG
        edge=(cfg.get_all_nodes(state)[0], cfg.get_all_nodes(transition['dst'])[0])
        cfg.graph.add_edge(edge[0],edge[1]) # adds edge if it doesn't already exist
        state=transition['dst']

    final_node=transitions[-1]['dst']
    path={'transitions':transitions, 'initial_node':initial_node, 'final_node':final_node}
    return end_state,cfg,path

# function code taken from https://stackoverflow.com/a/51827284
def find_repeated_sequences(s):
    match = re.findall(r'((\b.+?\b)(?:\s\2)+)', s)
    return [(m[1], int((len(m[0]) + 1) / (len(m[1]) + 1))) for m in match]

def generate_label_translator(labeled_cfg, raw_cfg, optimized_labeled_cfg):
    label_translator_optimized={}
    for labeled_node, raw_node in zip(labeled_cfg.nodes(), raw_cfg.nodes()):
        optimized_label=None
        for j in optimized_labeled_cfg.nodes():
            if str(labeled_node)==optimized_labeled_cfg._node[j]['old_label']:
                optimized_label=j
                break
        if optimized_label==None: raise Exception('Something happened.')
        label_translator_optimized[hex(raw_node.block_id)]=optimized_label

    label_translator={}
    for k in sorted(label_translator_optimized, key=label_translator_optimized.get, reverse=False):
        label_translator[k]=label_translator_optimized[k]

    return label_translator

def compress(path):
    transitions_merged_str = ''
    separator = '-'
    for transition in path['transitions']:
        transition = '%s%s%s%s%s' %(transition['jumpkind'], separator, transition['dst'], separator, transition['ret'])
        transitions_merged_str += '%s ' %transition

    repetitions = find_repeated_sequences(transitions_merged_str)

    # compress the execution path (remove consecutively repeating BBL sequences, i.e., "loops")
    for repetition in repetitions:
        sequence = '%s '%repetition[0] * int(repetition[1])
        transitions_merged_str = transitions_merged_str.replace(sequence, '%s '%repetition[0])
    # recreate the compressed execution path
    tmp = []
    for transition in transitions_merged_str.strip().split(' '):
        jumpkind,dst,ret = transition.split(separator)
        tmp.append({
            'jumpkind': jumpkind, 
            'dst': dst, 
            'ret': ret})

    sequence_lengths       = [] # list of sequence lengths
    sequence_repetitions   = [] # list of sequence repetitions
    sum_repetitions_length = 0  # sum of all repetitions (sum of all sequence lengths * total number of repetitions)
    number_of_repetitions  = len(repetitions) # total number of consecutively repeated sequences in execution path
    for repetition in repetitions:
        sequence_length = len(repetition[0].split(' '))
        sequence_lengths.append(sequence_length)
        sequence_repetitions.append(repetition[1])
        sum_repetitions_length += sequence_length * repetition[1] # sequence length * number of consecutive occurrences

    execution_path_length_pre_compression  = len(path['transitions'])
    execution_path_length_post_compression = len(tmp)

    mean_sequence_lengths      = 0
    mean_sequence_repetitions  = 0
    stdev_sequence_lengths     = 0
    stdev_sequence_repetitions = 0
    if number_of_repetitions>0:
        mean_sequence_lengths      = sum(sequence_lengths)/number_of_repetitions
        mean_sequence_repetitions  = sum(sequence_repetitions)/number_of_repetitions
        stdev_sequence_lengths     = statistics.pstdev(sequence_lengths)
        stdev_sequence_repetitions = statistics.pstdev(sequence_repetitions)

    stats = {
        'execution_path_length_pre_compression': execution_path_length_pre_compression,
        'repetitions': repetitions,
        'number_of_repetitions': number_of_repetitions,
        'mean_sequence_lengths': mean_sequence_lengths,
        'stdev_sequence_lengths': stdev_sequence_lengths,
        'mean_sequence_repetitions': mean_sequence_repetitions,
        'stdev_sequence_repetitions': stdev_sequence_repetitions,
        'execution_path_length_post_compression': execution_path_length_post_compression
    }
    path['transitions'] = tmp
    return path, stats

def hexify_labels(path):
    path['initial_node'] = hex(path['initial_node'])
    path['final_node']   = hex(path['final_node'])
    i=0
    while i<len(path['transitions']):
        path['transitions'][i]['dst'] = hex(path['transitions'][i]['dst'])
        if path['transitions'][i]['jumpkind'] == 'call':
            path['transitions'][i]['ret'] = hex(path['transitions'][i]['ret'])
        i+=1
    return path

def numify_labels(path, node_label_translator):
    path['initial_node'] = node_label_translator[path['initial_node']]
    path['final_node']   = node_label_translator[path['final_node']]
    i=0
    while i<len(path['transitions']):
        path['transitions'][i]['dst'] = node_label_translator[path['transitions'][i]['dst']]
        if path['transitions'][i]['jumpkind'] == 'call':
            path['transitions'][i]['ret'] = node_label_translator[path['transitions'][i]['ret']]
        i+=1
    return path

def write_execution_path(filename, path):
    with open(filename, 'w') as out:
        out.write('initial_node=%s final_node=%s\n' %(path['initial_node'], path['final_node']))
        for transition in path['transitions']:
            if transition['jumpkind'] == 'call':
                out.write('%s %s %s\n' %(transition['jumpkind'], transition['dst'], transition['ret']))
            else:
                out.write('%s %s\n' %(transition['jumpkind'], transition['dst']))

def get_addr(label, cfg):
    addr=None
    for node in list(cfg.graph.nodes()):
        if str(node)==label:
            addr=node.addr
            break
    return addr

def write_adjlist(filename, adjlist):
    with open(filename, 'w') as out:
        for node in adjlist: out.write(node+'\n')

def valid_execution_path(execution_path, adjlist): # checks if the execution path can traverse in the forward direction
    state = execution_path['initial_node']
    for transition in execution_path['transitions']:
        # print('transition:', transition)
        legal_destinations = adjlist[str(state)]
        if transition['dst'] in legal_destinations:
            state = transition['dst']
            # print('moved to node %s' %state)
        else:
            print(transition['dst'], 'not a neighbor of %s.' %state, 'Valid neighbors are:', legal_destinations)
            return False
    return str(state) == str(execution_path['final_node'])

def get_adjlist(cfg):
    adjlist_labels=list(nx.generate_adjlist(cfg.graph))
    adjlist=[]
    for node in adjlist_labels:
        addrs=''
        nodes=node.split('>')
        for _node in nodes:
            if _node=='': continue
            _node=str(_node).lstrip()+'>'
            addr=get_addr(_node,cfg)
            addrs+='%s '%hex(addr)
        adjlist.append(addrs.rstrip())
    return adjlist

def find_c_file(foldername):
    c_files = []
    for file in os.listdir(os.fsencode(foldername)):
        filename = os.fsdecode(file)
        if not filename.endswith('.c'): continue
        c_files.append(foldername + '/' + filename)
    return c_files

def run(application_foldername):
    output = ''
    c_filenames = find_c_file(application_foldername)
    out_file = application_foldername + '/main'

    compile(c_filenames, out_file) # compile the application using GCC

    proj = angr.Project(out_file, load_options={'auto_load_libs': False}) # load the compiled application
    cfg  = get_cfg(proj) # extract CFG
    end_state, cfg, path = get_execution_path(proj, cfg) # get example execution path

    # hexify the labels
    path = hexify_labels(path)

    labeled_cfg=nx.convert_node_labels_to_integers(cfg.graph, ordering='default')
    labeled_cfg_adjlist=list(nx.generate_adjlist(labeled_cfg))
    labeled_numified_adjlist=format_adjlist(labeled_cfg_adjlist)

    optimized_cfg=nx.DiGraph()
    for node,neighbors in labeled_numified_adjlist.items():
        optimized_cfg.add_node(node)
        for neighbor in neighbors:
            optimized_cfg.add_edge(node, neighbor)

    optimized_labeled_cfg=nx.convert_node_labels_to_integers(optimized_cfg, ordering='default',label_attribute='old_label')
    node_label_translator=generate_label_translator(labeled_cfg, cfg.graph, optimized_labeled_cfg)

    with open(application_foldername + '/translator', 'w') as out:
        for raw_address in node_label_translator:
            out.write('%s\n' %raw_address)

    output += '\n%s\n' %application_foldername
    output += 'Min addr: %s\n' %hex(proj.loader.min_addr)
    output += 'Max addr: %s (bitwidth=%s)\n' %(hex(proj.loader.max_addr),len(format(proj.loader.max_addr,'0b')))
    output += 'CFG has %d nodes and %d edges\n' %(len(cfg.graph.nodes()), len(cfg.graph.edges()))
    
    numified_adjlist=list(nx.generate_adjlist(optimized_labeled_cfg))
    write_adjlist(application_foldername+'/numified_adjlist', numified_adjlist)
    write_adjlist(application_foldername+'/adjlist', get_adjlist(cfg))

    numified_adjlist=format_adjlist(numified_adjlist)
    max_neighbors_set=max(numified_adjlist.values(),key=len)
    adjlist_encoded=encode_adjlist(numified_adjlist)
    levels_required=len(max([list(levels) for node,levels in adjlist_encoded], key=len))
    output += 'Adjacency list max_neighbors: %s %s\n' %(len(max_neighbors_set), max_neighbors_set)
    output += 'Bucket-rems pairs (levels) required to express the encoded adjacency list: %s\n' %levels_required
    # write raw execution path to file
    raw_path, raw_path_stats = compress(path.copy())
    write_execution_path('%s/recorded_path'%application_foldername, raw_path)
    # numify the execution path
    path = numify_labels(path, node_label_translator)
    path, stats = compress(path)
    # write numified execution path to file
    write_execution_path('%s/numified_path'%application_foldername, path)
    # write stats
    output += 'Execution path died because it: %s\n' %end_state
    output += 'Execution path length pre compression: %s\n' %stats['execution_path_length_pre_compression']
    output += 'Number of consecutively repeated sequences: %s\n' %stats['number_of_repetitions']
    output += 'Average (mean) length of sequences: %.2f (std=%.2f)\n' %(stats['mean_sequence_lengths'],stats['stdev_sequence_lengths'])
    output += 'Average (mean) number of sequence repetitions: %.2f (std=%.2f)\n' %(stats['mean_sequence_repetitions'],stats['stdev_sequence_repetitions'])
    output += 'Execution path length post compression: %s\n' %stats['execution_path_length_post_compression']
    # compute the maximum stack depth used during execution
    max_stack_depth=0
    cur_stack_depth=0
    for transition in path['transitions']:
        if transition['jumpkind']=='call':
            cur_stack_depth+=1
            if cur_stack_depth>max_stack_depth:
                max_stack_depth=cur_stack_depth
        elif transition['jumpkind']=='ret':
            cur_stack_depth-=1
    output += 'Max stack depth: %s\n' %max_stack_depth
    # test if the execution path is valid according to the adjacency list
    output += 'Execution path is valid according to the adjlist: %s\n' %valid_execution_path(path, numified_adjlist)
    return output

def write_stats(message, foldername=None, mode='w'):
    filename='stats.log'
    if foldername: filename = foldername + '/' + filename
    with open(filename, mode) as out:
        out.write(message+'\n')

def main(applications_dir, target_application_dir, exclude_dirs):
    merged_output = ''
    if target_application_dir!=None: # single application
        output=run(target_application_dir)
        write_stats(output, target_application_dir) # log stats to file
        merged_output+=output
    else:
        subfolders=[f.path for f in os.scandir(applications_dir) if f.is_dir()]
        if len(subfolders)==0:
            print('No applications found in: %s'%applications_dir)
            exit(2)
        for foldername in subfolders: # iterate over applications
            tmp=foldername
            if len(tmp.split('/'))>0:
                tmp=tmp.split('/')[-1]
            if tmp in exclude_dirs: continue
            output=run(foldername)
            write_stats(output, foldername) # log stats to file
            merged_output+=output
    print(merged_output)

def usage():
    print('Usage: %s [options]'%sys.argv[0])
    print('Options:')
    print('  -h               This help message')
    print('  -v               Verbose output')
    print('  -d <path/to/dir> Directory containing target applications organized into folders (default is to consider the \'./embench-iot-applications\' directory)')
    print('  -a <path>        Path to specific target application')
    print('  -e <name1,name2> Comma separated list of application folders to exclude')

if __name__ == '__main__':
    applications_dir='./embench-iot-applications'
    target_application_dir=None
    exclude_dirs=[]
    try:
        opts,args=getopt.getopt(sys.argv[1:],'hvd:a:e:')
    except getopt.GetoptError as err:
        print(err)
        usage()
        sys.exit(2)
    for opt,arg in opts:
        if opt=='-h':
            usage()
            sys.exit()
        elif opt=='-v':
            logging.getLogger('angr').setLevel('DEBUG')
        elif opt=='-d':
            if arg.endswith('/'): arg=arg[:-1]
            applications_dir=arg
        elif opt=='-a':
            if arg.endswith('/'): arg=arg[:-1]
            target_application_dir=arg
        elif opt=='-e':
            exclude_dirs=[foldername for foldername in arg.split(',')]
    main(applications_dir, target_application_dir, exclude_dirs)
