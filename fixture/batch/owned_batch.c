/* Repository-owned tiny throughput/receipt regression, not a realistic app. */
__attribute__((noinline)) int owned_add(int a,int b){return a+b;}
__attribute__((noinline)) int owned_select(int a){return a>5 ? a*3 : a-2;}
__attribute__((noinline)) int owned_mix(int a){return owned_add(owned_select(a),7);}
int main(void){return owned_mix(8);}
