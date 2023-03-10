package xjsnark.zekra_c6;

/*Generated by MPS */

import backend.structure.CircuitGenerator;
import backend.config.Config;
import backend.eval.SampleRun;
import java.math.BigInteger;
import backend.auxTypes.FieldElement;
import backend.auxTypes.UnsignedInteger;
import backend.auxTypes.SmartMemory;
import util.Util;
import backend.auxTypes.Bit;
import backend.auxTypes.ConditionalScopeTracker;
import backend.eval.CircuitEvaluator;

public class zekra_c6 extends CircuitGenerator {



  public static void main(String[] args) {
    Config.inputVerbose = false;
    Config.outputVerbose = false;
    Config.writeCircuits = false;
    new zekra_c6();
  }

  public zekra_c6() {
    super("zekra_c6");
    __generateCircuit();
    this.__evaluateSampleRun(new SampleRun("Sample_Run1", true) {
      public void pre() {
        for (int i = 0; i < EXECUTION_PATH_SIZE; i++) {
          EXECUTION_PATH[i][0].mapValue(BigInteger.ONE, CircuitGenerator.__getActiveCircuitGenerator().__getCircuitEvaluator());
          EXECUTION_PATH[i][1].mapValue(BigInteger.ONE, CircuitGenerator.__getActiveCircuitGenerator().__getCircuitEvaluator());
          EXECUTION_PATH[i][2].mapValue(BigInteger.ONE, CircuitGenerator.__getActiveCircuitGenerator().__getCircuitEvaluator());
          NUMIFIED_EXECUTION_PATH[i][0].mapValue(BigInteger.ONE, CircuitGenerator.__getActiveCircuitGenerator().__getCircuitEvaluator());
          NUMIFIED_EXECUTION_PATH[i][1].mapValue(BigInteger.ONE, CircuitGenerator.__getActiveCircuitGenerator().__getCircuitEvaluator());
        }
      }
      public void post() {
      }

    });

  }



  public void __init() {
    SHADOWSTACK = (FieldElement[]) FieldElement.createZeroArray(CircuitGenerator.__getActiveCircuitGenerator(), new int[]{SHADOWSTACK_DEPTH}, new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617"));
    EXECUTION_PATH = (FieldElement[][]) FieldElement.createZeroArray(CircuitGenerator.__getActiveCircuitGenerator(), new int[]{EXECUTION_PATH_SIZE, 3}, new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617"));
    NUMIFIED_EXECUTION_PATH = (FieldElement[][]) FieldElement.createZeroArray(CircuitGenerator.__getActiveCircuitGenerator(), new int[]{EXECUTION_PATH_SIZE, 2}, new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617"));
    shadowStackTop = new UnsignedInteger(4, new BigInteger("0"));
  }

  private FieldElement[] SHADOWSTACK;
  private FieldElement[][] EXECUTION_PATH;
  private FieldElement[][] NUMIFIED_EXECUTION_PATH;
  private UnsignedInteger shadowStackTop;
  private SmartMemory<FieldElement> shadowStackMem;

  private static int EXECUTION_PATH_SIZE = 30;
  private static int SHADOWSTACK_DEPTH = 15;
  @Override
  public void __defineInputs() {
    super.__defineInputs();















  }
  @Override
  public void __defineVerifiedWitnesses() {
    super.__defineVerifiedWitnesses();





    EXECUTION_PATH = (FieldElement[][]) FieldElement.createVerifiedWitnessArray(CircuitGenerator.__getActiveCircuitGenerator(), Util.getArrayDimensions(EXECUTION_PATH), new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617"));
    NUMIFIED_EXECUTION_PATH = (FieldElement[][]) FieldElement.createVerifiedWitnessArray(CircuitGenerator.__getActiveCircuitGenerator(), Util.getArrayDimensions(NUMIFIED_EXECUTION_PATH), new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617"));














  }
  @Override
  public void __defineWitnesses() {
    super.__defineWitnesses();

















  }
  public void outsource() {
    shadowStackMem = new SmartMemory(SHADOWSTACK, FieldElement.__getClassRef(), new Object[]{"21888242871839275222246405745257275088548364400416034343698204186575808495617"});

    // traverse the execution path 
    for (int i = 0; i < EXECUTION_PATH_SIZE; i++) {

      // jmpkind: 00 (jmp), 01 (call), 10 (ret), 11 (empty) 
      FieldElement jmpkind = EXECUTION_PATH[i][0].copy();
      FieldElement destNode = NUMIFIED_EXECUTION_PATH[i][0].copy();
      FieldElement retNode = NUMIFIED_EXECUTION_PATH[i][1].copy();

      // verify back edges using shadow stack (push return address on stack if call, check if destination address matches top value on stack if ret) 
      {
        Bit bit_h0d0y = jmpkind.isEqualTo(FieldElement.instantiateFrom(new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617"), 1)).copy();
        boolean c_h0d0y = CircuitGenerator.__getActiveCircuitGenerator().__checkConstantState(bit_h0d0y);
        if (c_h0d0y) {
          if (bit_h0d0y.getConstantValue()) {
            // add caller return address to shadow stack 
            push(retNode.copy());
          } else {
            {
              Bit bit_a0a0a0a2a7a3a42 = jmpkind.isEqualTo(FieldElement.instantiateFrom(new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617"), 2)).copy();
              boolean c_a0a0a0a2a7a3a42 = CircuitGenerator.__getActiveCircuitGenerator().__checkConstantState(bit_a0a0a0a2a7a3a42);
              if (c_a0a0a0a2a7a3a42) {
                if (bit_a0a0a0a2a7a3a42.getConstantValue()) {
                  // verify return address integrity 
                  FieldElement shadowAddr = pop().copy();
                  shadowAddr.forceEqual(destNode);
                } else {

                }
              } else {
                ConditionalScopeTracker.pushMain();
                ConditionalScopeTracker.push(bit_a0a0a0a2a7a3a42);
                // verify return address integrity 
                FieldElement shadowAddr = pop().copy();
                shadowAddr.forceEqual(destNode);

                ConditionalScopeTracker.pop();

                ConditionalScopeTracker.push(new Bit(true));

                ConditionalScopeTracker.pop();
                ConditionalScopeTracker.popMain();
              }

            }

          }
        } else {
          ConditionalScopeTracker.pushMain();
          ConditionalScopeTracker.push(bit_h0d0y);
          // add caller return address to shadow stack 
          push(retNode.copy());

          ConditionalScopeTracker.pop();

          ConditionalScopeTracker.push(new Bit(true));

          {
            Bit bit_a0a7a3a42_0 = jmpkind.isEqualTo(FieldElement.instantiateFrom(new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617"), 2)).copy();
            boolean c_a0a7a3a42_0 = CircuitGenerator.__getActiveCircuitGenerator().__checkConstantState(bit_a0a7a3a42_0);
            if (c_a0a7a3a42_0) {
              if (bit_a0a7a3a42_0.getConstantValue()) {
                // verify return address integrity 
                FieldElement shadowAddr = pop().copy();
                shadowAddr.forceEqual(destNode);
              } else {

              }
            } else {
              ConditionalScopeTracker.pushMain();
              ConditionalScopeTracker.push(bit_a0a7a3a42_0);
              // verify return address integrity 
              FieldElement shadowAddr = pop().copy();
              shadowAddr.forceEqual(destNode);

              ConditionalScopeTracker.pop();

              ConditionalScopeTracker.push(new Bit(true));

              ConditionalScopeTracker.pop();
              ConditionalScopeTracker.popMain();
            }

          }
          ConditionalScopeTracker.pop();
          ConditionalScopeTracker.popMain();
        }

      }
    }
  }
  private FieldElement pop() {
    FieldElement data = new FieldElement(new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617"), new BigInteger("0"));
    {
      Bit bit_b0ab = shadowStackTop.isNotEqualTo(UnsignedInteger.instantiateFrom(1, 0)).copy();
      boolean c_b0ab = CircuitGenerator.__getActiveCircuitGenerator().__checkConstantState(bit_b0ab);
      if (c_b0ab) {
        if (bit_b0ab.getConstantValue()) {
          shadowStackTop.assign(shadowStackTop.subtract(UnsignedInteger.instantiateFrom(1, 1)), 4);
          data.assign(shadowStackMem.read(shadowStackTop));
        } else {

        }
      } else {
        ConditionalScopeTracker.pushMain();
        ConditionalScopeTracker.push(bit_b0ab);
        shadowStackTop.assign(shadowStackTop.subtract(UnsignedInteger.instantiateFrom(1, 1)), 4);
        data.assign(shadowStackMem.read(shadowStackTop));

        ConditionalScopeTracker.pop();

        ConditionalScopeTracker.push(new Bit(true));

        ConditionalScopeTracker.pop();
        ConditionalScopeTracker.popMain();
      }

    }
    return data;
  }
  private void push(FieldElement data) {
    CircuitGenerator.__getActiveCircuitGenerator().__addOneAssertion(shadowStackTop.isNotEqualTo(UnsignedInteger.instantiateFrom(11, SHADOWSTACK_DEPTH)).getWire());
    shadowStackMem.write(shadowStackTop, data);
    shadowStackTop.assign(shadowStackTop.add(UnsignedInteger.instantiateFrom(1, 1)), 4);
  }

  public void __generateSampleInput(CircuitEvaluator evaluator) {
    __generateRandomInput(evaluator);
  }

}
