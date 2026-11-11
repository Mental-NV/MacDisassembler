.text
.globl _owned_bit_oracle
_owned_bit_oracle:
  tbz w0,#0,Ldone
  tbnz w1,#31,Ldone
  tbz x2,#32,Ldone
  tbnz x3,#63,Ldone
  tbz wzr,#7,Ldone
  tbnz xzr,#55,_owned_bit_oracle
Ldone:
  ret
