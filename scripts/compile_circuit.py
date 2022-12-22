#!/usr/bin/python3
#################################
## Author: Heini Bergsson Debes
#################################
# Purpose is to:
# (1) initialize the sizes of the data structures in the ZEKRA circuit
# (2) compile the high-level ZEKRA program code into the low-level arithmetic circuit (including formatting the circuit inputs) using the xjsnark backend

import sys, getopt, math
import subprocess

JUMPKIND_BITWIDTH=2
LABEL_BITWIDTH=None
BUCKET_BITWIDTH=None
ADDR_BITWIDTH=None
ADJLIST_SIZE=None
ADJLIST_LEVELS=None
EXECUTION_PATH_SIZE=None
SHADOWSTACK_DEPTH=None

ZEKRA_DIR='./zekra'
ZEKRA_COMPONENT_NAME='zekra'

COMPUTE_WORKLOAD_DISTRIBUTION=False

COMPONENTS_DIR='./components'

def compile(component_dir, component_name, with_poseidon=True):
    cmd = ['javac', '-d', 'bin', \
        '-cp', 'xjsnark_backend.jar', \
        '%s/%s.java'%(component_dir,component_name)]
    if with_poseidon: cmd.extend(['%s/PoseidonHash.java'%(component_dir)])
    # print(' '.join(cmd))
    subprocess.run(cmd, stderr=subprocess.PIPE, check=True)
    cmd = ['java', '-Xmx10g', \
        '-cp', 'bin:xjsnark_backend.jar', \
        'xjsnark.%s.%s'%(component_name,component_name)]
    # print(' '.join(cmd))
    output=subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    return output.stdout,output.stderr

def count_leading_whitespace(string):
    return len(string)-len(string.lstrip())

def set_shadow_stack_top_bitwidth(contents, bitwidth):
    for idx,line in enumerate(contents):
        replace_line=None
        if 'shadowStackTop = new UnsignedInteger(' in line:
            replace_line='%sshadowStackTop = new UnsignedInteger(%s, new BigInteger("0"));'
        if 'shadowStackTop.assign(shadowStackTop.subtract(UnsignedInteger.instantiateFrom(1, 1))' in line:
            replace_line='%sshadowStackTop.assign(shadowStackTop.subtract(UnsignedInteger.instantiateFrom(1, 1)), %s);'
        if 'shadowStackTop.assign(shadowStackTop.add(UnsignedInteger.instantiateFrom(1, 1))' in line:
            replace_line='%sshadowStackTop.assign(shadowStackTop.add(UnsignedInteger.instantiateFrom(1, 1)), %s);'
        if replace_line:
            contents[idx]=replace_line%(' '*count_leading_whitespace(line),bitwidth)
    return contents

def set_label_bitwidth(contents, bitwidth):
    for idx,line in enumerate(contents):
        replace_line=None
        if 'initialNode = new UnsignedInteger(' in line:
            replace_line='%sinitialNode = new UnsignedInteger(%s, new BigInteger("0"));'
        if 'initialNode = UnsignedInteger.createInput(this,' in line:
            replace_line='%sinitialNode = UnsignedInteger.createInput(this, %s);'
        if 'finalNode = new UnsignedInteger(' in line:
            replace_line='%sfinalNode = new UnsignedInteger(%s, new BigInteger("0"));'
        if 'finalNode = UnsignedInteger.createInput(this,' in line:
            replace_line='%sfinalNode = UnsignedInteger.createInput(this, %s);'
        if 'TRANSLATION_HINTS = (UnsignedInteger[][]) UnsignedInteger.createZeroArray(CircuitGenerator.__getActiveCircuitGenerator(), new int[]{EXECUTION_PATH_SIZE, 2},' in line:
            replace_line='%sTRANSLATION_HINTS = (UnsignedInteger[][]) UnsignedInteger.createZeroArray(CircuitGenerator.__getActiveCircuitGenerator(), new int[]{EXECUTION_PATH_SIZE, 2}, %s);'
        if 'TRANSLATION_HINTS = (UnsignedInteger[][]) UnsignedInteger.createWitnessArray(CircuitGenerator.__getActiveCircuitGenerator(), Util.getArrayDimensions(TRANSLATION_HINTS),' in line:
            replace_line='%sTRANSLATION_HINTS = (UnsignedInteger[][]) UnsignedInteger.createWitnessArray(CircuitGenerator.__getActiveCircuitGenerator(), Util.getArrayDimensions(TRANSLATION_HINTS), %s);'
        if 'dest = (UnsignedInteger[]) UnsignedInteger.createZeroArray(CircuitGenerator.__getActiveCircuitGenerator(), new int[]{EXECUTION_PATH_SIZE},' in line:
            replace_line='%sdest = (UnsignedInteger[]) UnsignedInteger.createZeroArray(CircuitGenerator.__getActiveCircuitGenerator(), new int[]{EXECUTION_PATH_SIZE}, %s);'
        if 'dest = (UnsignedInteger[]) UnsignedInteger.createWitnessArray(CircuitGenerator.__getActiveCircuitGenerator(), Util.getArrayDimensions(dest),' in line:
            replace_line='%sdest = (UnsignedInteger[]) UnsignedInteger.createWitnessArray(CircuitGenerator.__getActiveCircuitGenerator(), Util.getArrayDimensions(dest), %s);'
        if 'UnsignedInteger state = initialNode.copy(' in line:
            replace_line='%sUnsignedInteger state = initialNode.copy(%s);'
        if 'state.assign(uintDestNode,' in line:
            replace_line='%sstate.assign(uintDestNode, %s);'
        if 'UnsignedInteger uintDestNode = dest[i].copy(' in line:
            replace_line='%sUnsignedInteger uintDestNode = dest[i].copy(%s);'
        if 'UnsignedInteger bucket = uintDestNode.div(UnsignedInteger.instantiateFrom(4, 8)).copy(' in line:
            replace_line='%sUnsignedInteger bucket = uintDestNode.div(UnsignedInteger.instantiateFrom(4, 8)).copy(%s);'
        if 'CircuitGenerator.__getActiveCircuitGenerator().__addOneAssertion(shadowStackTop.isNotEqualTo(UnsignedInteger.instantiateFrom(' in line:
            replace_line='%sCircuitGenerator.__getActiveCircuitGenerator().__addOneAssertion(shadowStackTop.isNotEqualTo(UnsignedInteger.instantiateFrom(%s, SHADOWSTACK_DEPTH)).getWire());'
        if replace_line:
            contents[idx]=replace_line%(' '*count_leading_whitespace(line),bitwidth)
    return contents

def set_val(contents, data_structure, val):
    for idx,line in enumerate(contents):
        replace_line=None
        if 'int %s ='%data_structure in line:
            replace_line='%sprivate static int %s = %s;'
        if replace_line:
            contents[idx]=replace_line%(' '*count_leading_whitespace(line),data_structure,val)
            break
    return contents

def set_input_dir(contents, in_dir):
    for idx,line in enumerate(contents):
        replace_line=None
        if 'inputPathPrefix =' in line:
            replace_line='%sinputPathPrefix = "%s/";'
        if replace_line:
            contents[idx]=replace_line%(' '*count_leading_whitespace(line),in_dir)
            break
    return contents

def set_output_dir(contents, out_dir):
    for idx,line in enumerate(contents):
        replace_line=None
        if 'Config.outputFilesPath =' in line:
            replace_line='%sConfig.outputFilesPath = "%s";'
        if replace_line:
            contents[idx]=replace_line%(' '*count_leading_whitespace(line),out_dir)
            break
    return contents

def get_constraints(output):
    constraints=None
    for line in output.split('\n'):
        if 'Total Number of Constraints' in line:
            constraints=int(line.split(':')[1])
    return constraints

def successful_run(output):
    success=False
    for line in output.split('\n'):
        if 'Sample Run: Sample_Run1 finished!' in line:
            success=True
            break
    return success

def read_component(filename):
    program_lines=[]
    with open(filename, 'r') as in_file:
        for line in in_file.readlines():
            program_lines.append(line.replace('\n', ''))
    return program_lines

def write_component(filename, program_lines):
    with open(filename, 'w') as out_file:
        for line in program_lines: out_file.write('%s\r\n'%line)

def adjust_data_structures(program_lines):
    stack_top_bitwidth = int(math.log(SHADOWSTACK_DEPTH, 2))+1
    program_lines = set_shadow_stack_top_bitwidth(program_lines,stack_top_bitwidth)
    program_lines = set_val(program_lines,'JUMPKIND_BITWIDTH',JUMPKIND_BITWIDTH)
    program_lines = set_label_bitwidth(program_lines,LABEL_BITWIDTH)
    program_lines = set_val(program_lines,'BUCKET_BITWIDTH',BUCKET_BITWIDTH)
    program_lines = set_val(program_lines,'ADDR_BITWIDTH',ADDR_BITWIDTH)
    program_lines = set_val(program_lines,'ADJLIST_SIZE',ADJLIST_SIZE)
    program_lines = set_val(program_lines,'ADJLIST_LEVELS',ADJLIST_LEVELS)
    program_lines = set_val(program_lines,'EXECUTION_PATH_SIZE',EXECUTION_PATH_SIZE)
    program_lines = set_val(program_lines,'SHADOWSTACK_DEPTH',SHADOWSTACK_DEPTH)
    return program_lines

def configure_component(component_dir, component_name):
    filename='%s/%s.java'%(component_dir,component_name)
    program_lines=read_component(filename)
    program_lines=adjust_data_structures(program_lines)
    write_component(filename,program_lines)

def configure_main_component(in_dir, out_dir):
    filename='%s/%s.java'%(ZEKRA_DIR,ZEKRA_COMPONENT_NAME)
    program_lines=read_component(filename)
    program_lines=adjust_data_structures(program_lines)
    program_lines=set_input_dir(program_lines,in_dir)
    program_lines=set_output_dir(program_lines,out_dir)
    write_component(filename,program_lines)

def main(in_dir, out_dir):
    configure_main_component(in_dir, out_dir)
    stdout,stderr=compile(ZEKRA_DIR,ZEKRA_COMPONENT_NAME)
    total_constraints=get_constraints(stdout)
    
    print('Successfully compiled the ZEKRA circuit.\nTotal constraints: %s' %total_constraints)

    if not successful_run(stdout):
        print('Error output:\n')
        print(stdout)
        print(stderr)
        print('\n[-] Error Detected - Circuit was not satisfied with the inputs!')
        print('\tIf these inputs are used when generating a proof, then the verifier will reject it!')
        # exit(1)

    path_arith='%s.arith' %ZEKRA_COMPONENT_NAME
    path_formatted_input='%s_Sample_Run1.in' %ZEKRA_COMPONENT_NAME
    if out_dir != '':
        path_arith='%s/%s' %(out_dir,path_arith)
        path_formatted_input='%s/%s' %(out_dir,path_formatted_input)
    print('Arithmetic circuit stored in: %s' %path_arith)
    print('Formatted inputs stored in: %s' %path_formatted_input)

    if COMPUTE_WORKLOAD_DISTRIBUTION:
        print('\nCompiling individual components to find workload distribution.')

        with_poseidon=True
        components_constraints=[]
        for component in range(1,7):
            component_name='%s_c%s'%(ZEKRA_COMPONENT_NAME,component)
            component_dir='%s/%s'%(COMPONENTS_DIR,component_name)
            configure_component(component_dir,component_name)
            if component>3: with_poseidon=False
            stdout,stderr=compile(component_dir,component_name,with_poseidon)
            components_constraints.append(get_constraints(stdout))
        
        total_constraints_2 = sum(components_constraints)
        if total_constraints_2 != total_constraints: 
            print('[-] Error - Sum of all component constraints does not match that of the main ZEKRA circuit.')

        for idx,constraints in enumerate(components_constraints):
            workload=constraints/total_constraints_2*100
            print('Component #%s\'s constraints: %s (%.1f%% of total)' %((idx+1),constraints,workload))

def usage():
    print('Usage: %s --adjlist-len <num> --adjlist-levels <num> --path-len <num> --stack-depth <num> --label-bitwidth <num> --bucket-bitwidth <num> --address-bitwidth <num> [options]'%sys.argv[0])
    print('Options:')
    print('  -h                       This help message')
    print('  -v                       Output also how the workload (in number of constraints) is distributed among the six individual ZEKRA components/gadgets')
    print('  --zekra-dir <dir>        Path to the directory containing the ZEKRA Java files (default is %s)' %ZEKRA_DIR)
    print('  --adjlist-len <num>      Set <num> as the number of nodes in the adjacency list (adjacency lists < max must be padded before being passed as input)')
    print('  --adjlist-levels <num>   Set <num> as the number of levels used to represent each node\'s neighbors in the adjacency list')
    print('  --path-len <num>         Set <num> as the number of transitions in the execution path (execution paths < max must be padded before being passed as input)')
    print('  --stack-depth <num>      Set <num> as the maximum depth of the shadow stack data structure (execution paths that surpass this upper bound will cause the proof to become rejected so it must be set appropriately)')
    print('  --label-bitwidth <num>   Set <num> as the number of bits to represent each numified destination address when compressing/hashing the numified execution path')
    print('  --bucket-bitwidth <num>  Set <num> as the number of bits to represent each quotient (bucket) in the adjacency list encoding')
    print('  --address-bitwidth <num> Set <num> as the number of bits to represent each destination address when compressing/hashing the raw/recorded execution path')
    print('  --input-dir <dir>        Directory containing the output files from \'circuit_input_formatter.py\' (default is to check the current working directory)')
    print('  --output-dir <dir>       Store the <%s.arith> and <%s_Sample_Run1> files in <dir> (default is to store the files in the current working directory)' %(ZEKRA_COMPONENT_NAME,ZEKRA_COMPONENT_NAME))
    print('  --components-dir <dir>   If -v is used, then <dir> is the path to the directory containing the different ZEKRA components \'%s_c1,...,%s_c6\' (default is %s)' %(ZEKRA_COMPONENT_NAME,ZEKRA_COMPONENT_NAME,COMPONENTS_DIR))

if __name__ == '__main__':
    in_dir=''
    out_dir=''
    try:
        opts,args=getopt.getopt(sys.argv[1:],'hv',['zekra-dir=','adjlist-len=','adjlist-levels=','path-len=','stack-depth=','label-bitwidth=','bucket-bitwidth=','address-bitwidth=','input-dir=','output-dir=','components-dir='])
    except getopt.GetoptError as err:
        print(err)
        usage()
        sys.exit(2)
    for opt,arg in opts:
        if opt=='-h':
            usage()
            sys.exit()
        if opt=='-v':
            COMPUTE_WORKLOAD_DISTRIBUTION=True
        if opt=='--zekra-dir':
            if arg.endswith('/'): arg=arg[:-1]
            ZEKRA_DIR=arg
        elif opt=='--adjlist-len':
            ADJLIST_SIZE=int(arg)
        elif opt=='--adjlist-levels':
            ADJLIST_LEVELS=int(arg)
        elif opt=='--path-len':
            EXECUTION_PATH_SIZE=int(arg)
        elif opt=='--stack-depth':
            SHADOWSTACK_DEPTH=int(arg)
        elif opt=='--label-bitwidth':
            LABEL_BITWIDTH=int(arg)
        elif opt=='--bucket-bitwidth':
            BUCKET_BITWIDTH=int(arg)
        elif opt=='--address-bitwidth':
            ADDR_BITWIDTH=int(arg)
        elif opt=='--input-dir':
            if arg.endswith('/'): arg=arg[:-1]
            in_dir=arg
        elif opt=='--output-dir':
            if arg.endswith('/'): arg=arg[:-1]
            out_dir=arg
        elif opt=='--components-dir':
            if arg.endswith('/'): arg=arg[:-1]
            COMPONENTS_DIR=arg
    if not (ADJLIST_SIZE and ADJLIST_LEVELS and EXECUTION_PATH_SIZE and SHADOWSTACK_DEPTH and LABEL_BITWIDTH and BUCKET_BITWIDTH and ADDR_BITWIDTH):
        usage()
        sys.exit()
    main(in_dir, out_dir)
