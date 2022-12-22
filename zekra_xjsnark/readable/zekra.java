Program zekra { 
 
  public string inputPathPrefix = ""; 
   
  private int EMPTY_DEST_ADDR = 0; 
   
  // sizes of the data we are working with 
   
  private static int P_BITWIDTH = 254; 
   
  private static int JUMPKIND_BITWIDTH = 2; 
   
  private static int BUCKET_BITWIDTH = 7; 
   
  private static int ADDR_BITWIDTH = 40; 
   
  // sizes of the data structures that we want to express in the circuit 
   
  private static int ADJLIST_SIZE = 100; 
   
  private static int ADJLIST_LEVELS = 10; 
   
  private static int EXECUTION_PATH_SIZE = 30; 
   
  private static int SHADOWSTACK_DEPTH = 15; 
   
  // SHADOWSTACK[i] = return node label (LABEL_BITWIDTH bits) 
  private F_p[] SHADOWSTACK = new F_p[SHADOWSTACK_DEPTH]; 
  // ADJLIST[node label] = encoded neighbor list (ADJLIST_LEVELS*(BUCKET_BITWIDTH+8) bits) 
  private F_p[] ADJLIST = new F_p[ADJLIST_SIZE]; 
  // EXECUTION_PATH[i][0] = jumpkind (JUMPKIND_BITWIDTH bits), EXECUTION_PATH[i][1] = raw/recorded destination address (ADDR_BITWIDTH bits), EXECUTION_PATH[i][2] = raw/recorded return address (ADDR_BITWIDTH bits) 
  private F_p[][] EXECUTION_PATH = new F_p[EXECUTION_PATH_SIZE][3]; 
  // NUMIFIED_EXECUTIONPATH[i][0] = numerical destination node label (LABEL_BITWIDTH bits), NUMIFIED_EXECUTIONPATH[i][1] = numerical return node label (LABEL_BITWIDTH bits) 
  private F_p[][] NUMIFIED_EXECUTION_PATH = new F_p[EXECUTION_PATH_SIZE][2]; 
  // TRANSLATOR[node label] = raw address corresponding to numified node label (ADDR_BITWIDTH bits) - the last entry contains the empty move's destination address 
  private F_p[] TRANSLATOR = new F_p[ADJLIST_SIZE + 1]; 
   
  // TRANSLATION_HINTS[i][0] = index of EXECUTION_PATH[i][1] in TRANSLATOR, TRANSLATION_HINTS[i][1] = index of EXECUTION_PATH[i][2] in TRANSLATOR 
  private uint_11[][] TRANSLATION_HINTS = new uint_11[EXECUTION_PATH_SIZE][2]; 
   
  // H(PAD(COMPRESS(ADJLIST||nonceAdjlist))) 
  private F_p adjListDigest; 
  // H(PAD(COMPRESS(EXECUTION_PATH||nonceVerifier||noncePath))) 
  private F_p executionPathDigest; 
  // H(PAD(COMPRESS(TRANSLATOR||nonceTranslator))) 
  private F_p translatorDigest; 
   
  // note that if SHADOWSTACK_DEPTH > 7 then we need more than 3 bits to represent shadowStackTop 
  // if SHADOWSTACK_DEPTH = 15, then use uint_4 (if SHADOWSTACK_DEPTH = 7, use uint_3) 
  private uint_4 shadowStackTop = 0; 
  private uint_11 initialNode; 
  private uint_11 finalNode; 
   
  // nonces 
  private F_p nonceVerifier; 
  private F_p noncePath; 
  private F_p nonceAdjlist; 
  private F_p nonceTranslator; 
   
  // helper data (i.e., hints) computed by the worker and verified inside the circuit 
  private uint_8[][] eAndR1 = new uint_8[EXECUTION_PATH_SIZE][2]; 
  private F_p[][] neighborEq = new F_p[EXECUTION_PATH_SIZE][ADJLIST_LEVELS * 2]; 
  private F_p[][] neighborExistsProof = new F_p[EXECUTION_PATH_SIZE][5]; 
   
  // converting a field element to uint when updating the position (state) in the CFG is expensive so we accept the numified destination also as a uint and then verify that it corresponds to the corresponding field element in the circuit which is much cheaper 
  private uint_11[] dest = new uint_11[EXECUTION_PATH_SIZE]; 
   
  // data structures used inside the circuit 
  private RAM <F_p> adjListMem; 
  private RAM <F_p> shadowStackMem; 
  private RAM <F_p> translatorMem; 
   
  inputs { 
    initialNode, finalNode, nonceVerifier, adjListDigest, executionPathDigest, translatorDigest 
  } 
   
  witnesses_AssertRange { 
    EXECUTION_PATH, ADJLIST, neighborEq, neighborExistsProof, noncePath, NUMIFIED_EXECUTION_PATH, TRANSLATOR, nonceAdjlist, nonceTranslator  
  } 
   
  witnesses { 
    eAndR1, dest, TRANSLATION_HINTS  
  } 
   
  public void outsource() { 
    if ((BUCKET_BITWIDTH + 8) * ADJLIST_LEVELS >= P_BITWIDTH) { throw new IllegalArgumentException("(BUCKET_BITWIDTH+8)*ADJ_LIST_LEVELS cannot exceed p's bitwidth"); } 
     
    // code executed outside the circuit 
    external { 
        BigInteger state = initialNode.val; 
        for (int i = 0; i < EXECUTION_PATH_SIZE; i++) { 
          BigInteger[] quotients = new BigInteger[ADJLIST_LEVELS]; 
          BigInteger[] remainders = new BigInteger[ADJLIST_LEVELS]; 
          BigInteger[] neighbourExistsProofVals = new BigInteger[5]; 
          BigInteger[] eAndR1Vals = new BigInteger[2]; 
           
          for (int j = 0; j < ADJLIST_LEVELS; j++) { 
            quotients[j] = BigInteger.ZERO; 
            remainders[j] = BigInteger.ZERO; 
          } 
          for (int j = 0; j < neighbourExistsProofVals.length; j++) { 
            neighbourExistsProofVals[j] = BigInteger.ZERO; 
          } 
          for (int j = 0; j < eAndR1Vals.length; j++) { 
            eAndR1Vals[j] = BigInteger.ZERO; 
          } 
           
          BigInteger destNode = NUMIFIED_EXECUTION_PATH[i][0].val; 
          BigInteger pos = destNode.mod(BigInteger.valueOf(8)); 
          BigInteger bucket = destNode.divide(BigInteger.valueOf(8)); 
           
          if (!destNode.equals(BigInteger.valueOf(ADJLIST_SIZE))) { 
            BigInteger currNodeAdjList = ADJLIST[state.intValue()].val; 
             
            for (int j = 0, k = 0; j < ADJLIST_LEVELS; j++, k += (BUCKET_BITWIDTH + 8)) { 
              quotients[j] = currNodeAdjList.shiftRight(k).and(BigInteger.valueOf(2).pow(BUCKET_BITWIDTH).subtract(BigInteger.valueOf(1))); 
              remainders[j] = currNodeAdjList.shiftRight(k + BUCKET_BITWIDTH).and(BigInteger.valueOf(255)); 
               
              // if the destination node exists at this level of the adjacency list 
              if (bucket.equals(quotients[j]) && remainders[j].testBit(pos.intValue())) { 
                // e 
                neighbourExistsProofVals[0] = BigInteger.valueOf(2).pow(pos.intValue()); 
                // q1 
                neighbourExistsProofVals[1] = new BigDecimal(remainders[j]).divide(new BigDecimal(neighbourExistsProofVals[0]), RoundingMode.FLOOR).toBigInteger(); 
                // r1 
                neighbourExistsProofVals[2] = remainders[j].mod(neighbourExistsProofVals[0]); 
                // q2 
                neighbourExistsProofVals[3] = neighbourExistsProofVals[1].divide(BigInteger.valueOf(2)); 
                // r2 
                neighbourExistsProofVals[4] = neighbourExistsProofVals[1].mod(BigInteger.valueOf(2)); 
                 
                eAndR1Vals[0] = neighbourExistsProofVals[0]; 
                eAndR1Vals[1] = neighbourExistsProofVals[2]; 
              } 
            } 
          } 
           
          for (int j = 0, k = 0; j < ADJLIST_LEVELS; j++, k += 2) { 
            neighborEq[i][k].val = quotients[j]; 
            neighborEq[i][k + 1].val = remainders[j]; 
          } 
          for (int j = 0; j < neighbourExistsProofVals.length; j++) { 
            neighborExistsProof[i][j].val = neighbourExistsProofVals[j]; 
          } 
          for (int j = 0; j < eAndR1Vals.length; j++) { 
            eAndR1[i][j].val = eAndR1Vals[j]; 
          } 
           
          state = destNode; 
        } 
    } 
     
     
    // ///////////////////////////////////////////////////// 
    // the remaining code is compiled into the ZEKRA circuit 
     
    adjListMem = INIT_RAM <F_p>(ADJLIST); 
    shadowStackMem = INIT_RAM <F_p>(SHADOWSTACK); 
    translatorMem = INIT_RAM <F_p>(TRANSLATOR); 
     
     
    // //////////////////////////// 
    // Begin by verifying the translator, execution path, and adjacency list 
     
    // first verify authenticity of adjacency list 
    int neighbors_bitwidth = ADJLIST_LEVELS * (BUCKET_BITWIDTH + 8); 
    F_p[] adjlist_compressed = compress(ADJLIST, neighbors_bitwidth); 
    F_p[] adjlist_padded = make_multiple_of(adjlist_compressed, 8, 1); 
    adjlist_padded[adjlist_padded.length - 1] = nonceAdjlist; 
    F_p tmp_adjlist_digest = hash(adjlist_padded); 
    log ( tmp_adjlist_digest , "computed adjlist digest" ); 
    log ( adjListDigest , "input adjlist digest" ); 
    verifyEq ( tmp_adjlist_digest , adjListDigest ); 
     
    // then verify authenticity of execution path 
    int transition_bitwidth = JUMPKIND_BITWIDTH + ADDR_BITWIDTH * 2; 
    F_p[] path_compressed = compress(EXECUTION_PATH, transition_bitwidth); 
    F_p[] path_padded = make_multiple_of(path_compressed, 8, 2); 
    path_padded[path_padded.length - 2] = nonceVerifier; 
    path_padded[path_padded.length - 1] = noncePath; 
    F_p tmp_path_digest = hash(path_padded); 
    log ( tmp_path_digest , "computed path digest" ); 
    log ( executionPathDigest , "input path digest" ); 
    verifyEq ( tmp_path_digest , executionPathDigest ); 
     
    // then verify authenticity of translator 
    F_p[] translator_compressed = compress(TRANSLATOR, ADDR_BITWIDTH); 
    F_p[] translator_padded = make_multiple_of(translator_compressed, 8, 1); 
    translator_padded[translator_padded.length - 1] = nonceTranslator; 
    F_p tmp_translator_digest = hash(translator_padded); 
    log ( tmp_translator_digest , "computed translator digest" ); 
    log ( translatorDigest , "input translator digest" ); 
    verifyEq ( tmp_translator_digest , translatorDigest ); 
     
     
    // //////////////////////////// 
    // Then verify that the translation of the raw execution path to the numified execution path was done correctly 
    // NOTE: this component prevents feeding isomorphic graphs by including the translation in the proof 
    for (int i = 0; i < EXECUTION_PATH_SIZE; i++) { 
      verifyEq ( translatorMem[TRANSLATION_HINTS[i][0]] , EXECUTION_PATH[i][1] ); 
      verifyEq ( translatorMem[TRANSLATION_HINTS[i][1]] , EXECUTION_PATH[i][2] ); 
      verifyEq ( F_p(TRANSLATION_HINTS[i][0]) , NUMIFIED_EXECUTION_PATH[i][0] ); 
      verifyEq ( F_p(TRANSLATION_HINTS[i][1]) , NUMIFIED_EXECUTION_PATH[i][1] ); 
    } 
     
     
    // //////////////////////////// 
    // Then proceed to verify forward and back edges using the numified execution path 
     
    // start from the initial node 
    uint_11 state = initialNode; 
     
    // traverse the execution path 
    for (int i = 0; i < EXECUTION_PATH_SIZE; i++) { 
       
      // jmpkind: 00 (jmp), 01 (call), 10 (ret), 11 (empty) 
      F_p jmpkind = EXECUTION_PATH[i][0]; 
      F_p destNode = NUMIFIED_EXECUTION_PATH[i][0]; 
      F_p retNode = NUMIFIED_EXECUTION_PATH[i][1]; 
       
      // verify forward edges (ignore empty moves to facilitate dynamic path lengths) 
      if (jmpkind NEQ F_p(3)) { 
         
        uint_11 uintDestNode = dest[i]; 
        verifyEq ( destNode , F_p(uintDestNode) ); 
        uint_11 bucket = uintDestNode / uint_4(8); 
        uint_3 pos = uint_3(uintDestNode % uint_4(8)); 
         
        // retrieve the neighbour list of the current node 
        F_p currNodeNeighbors = adjListMem[state]; 
         
        // v.t. neighbor equation equals the current node's neighbors 
        F_p neighborEqProd = 0; 
        for (int j = 0, k = 0; j < ADJLIST_LEVELS * 2; j += 2, k += (BUCKET_BITWIDTH + 8)) { 
          neighborEqProd = neighborEqProd + neighborEq[i][j] * F_p(BigInteger.valueOf(2).pow(k)); 
          neighborEqProd = neighborEqProd + neighborEq[i][j + 1] * F_p(BigInteger.valueOf(2).pow(k + BUCKET_BITWIDTH)); 
        } 
        verifyEq ( neighborEqProd , currNodeNeighbors ); 
         
        // v.t. h * 2 + k = f 
        verifyEq ( neighborExistsProof[i][3] * F_p(2) + neighborExistsProof[i][4] , neighborExistsProof[i][1] ); 
        // v.t. bit at pos is set 
        verifyEq ( neighborExistsProof[i][4] , F_p(1) ); 
         
        // v.t. e=2**(destNode%8) 
        // efficient linear search to find if there is some j s.t. e = 2**j AND pos=j, where pos is computed inside the circuit as pos=destNode%8 
        F_p validExp = F_p(1); 
        for (double j = 0, k = 1; j < 8; j++, k = Math.pow(2, j)) { 
          validExp = validExp * ((F_p(pos) - F_p(new Double(j).intValue())) + (neighborExistsProof[i][0] - F_p(new Double(k).intValue()))); 
        } 
        verifyEq ( validExp , F_p(0) ); 
         
        // v.t. g < e 
        verifyEq ( F_p(eAndR1[i][0]) , neighborExistsProof[i][0] ); 
        verifyEq ( F_p(eAndR1[i][1]) , neighborExistsProof[i][2] ); 
        verify ( eAndR1[i][0] > eAndR1[i][1] ); 
         
        // v.t. destNode exists at some level in the adjacency list 
        F_p destNodeExists = F_p(1); 
        for (int j = 0; j < ADJLIST_LEVELS * 2; j += 2) { 
          // v.t. f * e + g = rems 
          F_p remaindersMatch = neighborExistsProof[i][1] * neighborExistsProof[i][0] + neighborExistsProof[i][2] - neighborEq[i][j + 1]; 
          F_p bucketMatch = F_p(bucket) - neighborEq[i][j]; 
          // v.t. remaindersMatch and bucketMatch 
          destNodeExists = destNodeExists * (remaindersMatch + bucketMatch); 
        } 
        verifyEq ( destNodeExists , F_p(0) ); 
         
        // update position in the CFG 
        state = uintDestNode; 
      } 
       
      // verify back edges using shadow stack (push return address on stack if call, check if destination address matches top value on stack if ret) 
      if (jmpkind EQ F_p(1)) { 
        // add caller return address to shadow stack 
        push(retNode); 
      } else if (jmpkind EQ F_p(2)) { 
        // verify return address integrity 
        F_p shadowAddr = pop(); 
        verifyEq ( shadowAddr , destNode ); 
      } 
    } 
     
    verifyEq ( state , finalNode ); 
  } 
   
  private F_p[] compress(F_p[] tmp_list, int elem_bitwidth) { 
    if (elem_bitwidth >= P_BITWIDTH) { throw new IllegalArgumentException("elem_bitwidth cannot exceed p's bitwidth"); } 
     
    int elems_per_field_element = Math.floorDiv(P_BITWIDTH, elem_bitwidth); 
    F_p[] compressed = new F_p[((int) Math.ceil(((double) tmp_list.length) / elems_per_field_element))]; 
     
    for (int i = 0; i < compressed.length; i++) { 
      int tmp_list_idx = i * elems_per_field_element; 
      for (int j = 0, k = 0; j < elems_per_field_element && tmp_list_idx < tmp_list.length; j++, k += elem_bitwidth, tmp_list_idx++) { 
        F_p elem = tmp_list[tmp_list_idx]; 
        compressed[i] = compressed[i] + (elem * F_p(BigInteger.valueOf(2).pow(k))); 
      } 
    } 
    return compressed; 
  } 
   
  private F_p[] compress(F_p[][] tmp_list, int elem_bitwidth) { 
    if (elem_bitwidth >= P_BITWIDTH) { throw new IllegalArgumentException("elem_bitwidth cannot exceed p's bitwidth"); } 
     
    int elems_per_field_element = Math.floorDiv(P_BITWIDTH, elem_bitwidth); 
    F_p[] compressed = new F_p[((int) Math.ceil(((double) tmp_list.length) / elems_per_field_element))]; 
     
    for (int i = 0; i < compressed.length; i++) { 
      int tmp_list_idx = i * elems_per_field_element; 
      for (int j = 0, k = 0; j < elems_per_field_element && tmp_list_idx < tmp_list.length; j++, k += elem_bitwidth, tmp_list_idx++) { 
        F_p[] elem = tmp_list[tmp_list_idx]; 
        F_p concatenated = elem[0]; 
        concatenated = concatenated + (elem[1] * F_p(BigInteger.valueOf(2).pow(JUMPKIND_BITWIDTH))); 
        concatenated = concatenated + (elem[2] * F_p(BigInteger.valueOf(2).pow(JUMPKIND_BITWIDTH + ADDR_BITWIDTH))); 
        compressed[i] = compressed[i] + (concatenated * F_p(BigInteger.valueOf(2).pow(k))); 
      } 
    } 
    return compressed; 
  } 
   
  private F_p[] make_multiple_of(F_p[] tmp_list, int factor, int extend) { 
    int padded_len = (int) Math.ceil(((double) (tmp_list.length + extend)) / factor) * factor; 
    F_p[] padded = new F_p[padded_len]; 
     
    for (int i = 0; i < tmp_list.length; i++) { 
      padded[i] = tmp_list[i]; 
    } 
    for (int i = tmp_list.length; i < padded_len; i++) { 
      padded[i] = F_p(0); 
    } 
    return padded; 
  } 
   
  private F_p hash(F_p[] padded_list) { 
    // hash first chunk 
    F_p[] poseidon_state = new F_p[9]; 
    poseidon_state[0] = F_p(0); 
    for (int i = 0; i < 8; i++) { 
      poseidon_state[i + 1] = F_p(padded_list[i]); 
    } 
    poseidon_state = PoseidonHash.poseidon_hash_8(poseidon_state); 
     
    // hash remaining chunks 
    int remaining_chunks = (padded_list.length / 8) - 1; 
    for (int i = 0; i < remaining_chunks; i++) { 
      for (int j = 0; j < 8; j++) { 
        poseidon_state[j + 1] = F_p(padded_list[(i + 1) * 8 + j]) + poseidon_state[j + 1]; 
      } 
      poseidon_state = PoseidonHash.poseidon_hash_8(poseidon_state); 
    } 
    return poseidon_state[2]; 
  } 
   
  private F_p pop() { 
    F_p data = 0; 
    if (shadowStackTop NEQ uint_1(0)) { 
      shadowStackTop = shadowStackTop - uint_1(1); 
      data = shadowStackMem[shadowStackTop]; 
    } 
    return data; 
  } 
   
  private void push(F_p data) { 
    verify ( shadowStackTop NEQ uint_11(SHADOWSTACK_DEPTH) ); 
    shadowStackMem[shadowStackTop] = data; 
    shadowStackTop = shadowStackTop + uint_1(1); 
  } 
   
  SampleRun("Sample_Run1", true){ 
    pre { 
        string line; 
        int i = 0; 
        try { 
          BufferedReader br = new BufferedReader(new FileReader(inputPathPrefix + "in_encoded_adjlist")); 
          while ((line = br.readLine()) != null) { 
            ADJLIST[i].val = new BigInteger(line, 10); 
            i = i + 1; 
          } 
           
          br = new BufferedReader(new FileReader(inputPathPrefix + "in_translator")); 
          i = 0; 
          while ((line = br.readLine()) != null) { 
            TRANSLATOR[i].val = new BigInteger(line, 10); 
            i = i + 1; 
          } 
           
          br = new BufferedReader(new FileReader(inputPathPrefix + "in_recorded_path")); 
          i = 0; 
          while ((line = br.readLine()) != null) { 
            String[] transition = line.split(" "); 
            BigInteger jmpkind = new BigInteger(transition[0], 10); 
            BigInteger destAddr = new BigInteger(transition[1], 10); 
            BigInteger retAddr = new BigInteger(transition[2], 10); 
            EXECUTION_PATH[i][0].val = jmpkind; 
            EXECUTION_PATH[i][1].val = destAddr; 
            EXECUTION_PATH[i][2].val = retAddr; 
            i = i + 1; 
          } 
           
          br = new BufferedReader(new FileReader(inputPathPrefix + "in_numified_path")); 
          i = 0; 
          while ((line = br.readLine()) != null) { 
            String[] transition = line.split(" "); 
            BigInteger destLabel = new BigInteger(transition[0], 10); 
            BigInteger retLabel = new BigInteger(transition[1], 10); 
            NUMIFIED_EXECUTION_PATH[i][0].val = destLabel; 
            NUMIFIED_EXECUTION_PATH[i][1].val = retLabel; 
            dest[i].val = destLabel; 
            i = i + 1; 
          } 
           
          br = new BufferedReader(new FileReader(inputPathPrefix + "in_initial_node")); 
          initialNode.val = new BigInteger(br.readLine(), 10); 
          br = new BufferedReader(new FileReader(inputPathPrefix + "in_final_node")); 
          finalNode.val = new BigInteger(br.readLine(), 10); 
          br = new BufferedReader(new FileReader(inputPathPrefix + "in_nonce_verifier")); 
          nonceVerifier.val = new BigInteger(br.readLine(), 10); 
          br = new BufferedReader(new FileReader(inputPathPrefix + "in_nonce_path")); 
          noncePath.val = new BigInteger(br.readLine(), 10); 
          br = new BufferedReader(new FileReader(inputPathPrefix + "in_nonce_adjlist")); 
          nonceAdjlist.val = new BigInteger(br.readLine(), 10); 
          br = new BufferedReader(new FileReader(inputPathPrefix + "in_nonce_translator")); 
          nonceTranslator.val = new BigInteger(br.readLine(), 10); 
          br = new BufferedReader(new FileReader(inputPathPrefix + "in_encoded_adjlist_digest")); 
          adjListDigest.val = new BigInteger(br.readLine(), 10); 
          br = new BufferedReader(new FileReader(inputPathPrefix + "in_recorded_path_digest")); 
          executionPathDigest.val = new BigInteger(br.readLine(), 10); 
          br = new BufferedReader(new FileReader(inputPathPrefix + "in_translator_digest")); 
          translatorDigest.val = new BigInteger(br.readLine(), 10); 
           
          // create hints for verifying that the translation was done correctly inside the circuit 
          for (int j = 0; j < EXECUTION_PATH_SIZE; j++) { 
            // if destination targets the empty move 
            if (EXECUTION_PATH[j][1].val.equals(BigInteger.valueOf(EMPTY_DEST_ADDR))) { 
              TRANSLATION_HINTS[j][0].val = BigInteger.valueOf(ADJLIST_SIZE); 
            } else { 
              for (int k = 0; k < TRANSLATOR.length; k++) { 
                if (TRANSLATOR[k].val.equals(EXECUTION_PATH[j][1].val)) { 
                  TRANSLATION_HINTS[j][0].val = BigInteger.valueOf(k); 
                  break; 
                } 
              } 
            } 
            // if return targets the empty move 
            if (EXECUTION_PATH[j][2].val.equals(BigInteger.valueOf(EMPTY_DEST_ADDR))) { 
              TRANSLATION_HINTS[j][1].val = BigInteger.valueOf(ADJLIST_SIZE); 
            } else { 
              for (int k = 0; k < TRANSLATOR.length; k++) { 
                if (TRANSLATOR[k].val.equals(EXECUTION_PATH[j][2].val)) { 
                  TRANSLATION_HINTS[j][1].val = BigInteger.valueOf(k); 
                  break; 
                } 
              } 
            } 
          } 
        } catch (Exception ex) { 
          System.out.println(ex.getMessage().toString()); 
        } 
    } 
    post { 
        <no statements> 
    } 
  } 
   
   
  public static void main(string[] args) { 
    Config.outputVerbose = true; 
    Config.inputVerbose = false; 
    Config.debugVerbose = true; 
    Config.writeCircuits = true; 
    Config.outputFilesPath = ""; 
  } 
}