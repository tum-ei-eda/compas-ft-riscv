/* Keep the DMR callee separate from its control-flow-protected caller. */
__attribute__((noinline)) unsigned long abi_selective_leaf(unsigned long value)
{
    return 3*value + 5;
}
