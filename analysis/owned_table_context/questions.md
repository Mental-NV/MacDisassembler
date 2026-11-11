# Frozen blind behavior questions

Answer separately for each selected function, using only the provided binary
receipts and the existing allowed analysis tools. Do not read source, build
or oracle notes. Do not execute the library or guess application semantics.

1. What does the function return, and under what conditions?
2. How is its scalar input transformed? Explain signedness and the consequence
   for negative inputs; distinguish remainder from mathematical modulo.
3. Does it read a table? Establish its address source, element width, iteration
   bound, byte footprint and byte order from cited instructions/evidence.
4. If the table is statically identifiable, recover its exact signed values with
   file/address/byte provenance. Which stored values could affect the result,
   given the input transformation? Separate stored bytes from reachable matches.
5. If table identity or contents depend on runtime input, state precisely what
   remains unknown. Do not substitute a nearby static object for an unknown pointer.
6. Identify evidence gaps and what additional static evidence, if any, could
   resolve them. Do not infer a domain such as dates, hours or calendar behavior.

For each claim cite receipt/function and instruction/address or byte-range
references. Record tool calls, manual decoding steps, errors, elapsed time when
available, and confidence/uncertainty. A useful answer can say “not established.”
