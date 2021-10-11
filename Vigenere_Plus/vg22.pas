{

VigerePlus (version 2.2) - simple 512 bit block CBC-mode encryption algorithm based on 2-round Vigenere cipher, 
includes byte-by-byte block permutation and transformation, bit rotation and 4 mutating 512-bit session keys.

Written by Alexander Myasnikov, Kolchugino, Vladimir region, Russia

August, 2008

E-Mail: darksoftware@ya.ru

Web: www.darksoftware.narod.ru

Freeware, open source, free for any usage, not patented

This is only idea, working idea. There are some bugs? Code is slow and not optimized. 


}




unit vg22;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes;


type tprocessproc = procedure (done: integer);
type pprocessproc = ^tprocessproc;


function vgcrypt22 (fi,ft: string;skey: string;dir: byte; process: pprocessproc=nil): boolean;


implementation




uses DCPsha512, DCPhaval;

var p_tab: array [0..255] of byte; // Substtable for data mutation (encryption)

var p_dtab: array [0..255] of byte; // Substtable for data mutation (decryption)





procedure XORBuff(I1, I2: Pointer; Size: Integer; Dest: Pointer); assembler;  // Buffer xoring

asm
       AND   ECX,ECX
       JZ    @@5
       PUSH  ESI
       PUSH  EDI
       MOV   ESI,EAX
       MOV   EDI,Dest
@@1:   TEST  ECX,3
       JNZ   @@3
@@2:   SUB   ECX,4
       JL    @@4
       MOV   EAX,[ESI + ECX]
       XOR   EAX,[EDX + ECX]
       MOV   [EDI + ECX],EAX
       JMP   @@2
@@3:   DEC   ECX
       MOV   AL,[ESI + ECX]
       XOR   AL,[EDX + ECX]
       MOV   [EDI + ECX],AL
       JMP   @@1
@@4:   POP   EDI
       POP   ESI
@@5:
end;



{
procedure XORBuff(I1, I2: Pointer; Size: Integer; Dest: Pointer);
begin
Move(i1^,dest^,size);
end;
}

type tkey= array  [0..63] of byte; // Key data


var p_tab64: TKey; // Substtable for data mutation (encryption)

var p_dtab64: TKey; // Substtable for data mutation (decryption)


type
  Bit = 0..1;

type
  TBitSet = array[0..7] of Bit;


function xSucc64(b: byte; s: byte): byte;  // Rotate 64
begin

if (b+s)>63  then begin
result:=(b+s)-63-1;
end else result:=b+s;
end;



function xSucc8(b: byte; s: byte): byte;  // Rotate bits
begin

if (b+s)>7  then begin
result:=(b+s)-7-1;
end else result:=b+s;
end;


function xPred8(b: byte;s: byte): byte;  // Rotate bits
begin

if (b-s)<0  then begin
result:=8-s+b;
end else result:=b-s;
end;


function GetNBit(X, N: byte): Bit;
begin
  Result := x shr N and 1;
end;

function GetBits(X: byte): TBitSet;

var
  N: integer;
begin
  for N := 0 to 7 do
    Result[N] := GetNBit(X, N);
end;

function MakeByte(BitSet: TBitSet): byte;

var
  i: integer;
begin
  Result := 0;
  for i := 7 downto 0 do
    Result := Result shl 1 + (BitSet[i] and 1);
end;


function BitRotf(b,r : byte): byte;
var i: integer; x,y: TBitset;
begin

x:= GetBits(b);
for I := 0 to 7 do begin
y[i]:=x[xsucc8(i,r)];
end;

result:=MakeByte(y);

end;


function BitRotb(b,r : byte): byte;
var i: integer; x,y: TBitset;
begin
x:= GetBits(b);
for I := 0 to 7 do begin
y[i]:=x[xpred8(i,r)];
end;

result:=MakeByte(y);

end;


function GetBitsSum(X: byte): byte;
var
  N: integer;
begin
Result:=0;
  for N := 0 to 7 do
    Result:= Result + GetNBit(X, N);

end;

function GetBitsSum64(X: tkey): byte;
var
  N,I: integer;
begin
Result:=0;
for i:=0 to 7 do
  for N := 0 to 7 do
    Result:= Result + GetNBit(X[i], N);

end;


function xSucc(b: byte; s: byte): byte;  // Rotate bytes
begin
if (b+s)>255  then begin
result:=(b+s)-255-1;
end else result:=b+s;
end;


function xPred(b: byte;s: byte): byte;  // Rotate bytes
begin
if (b-s)<0  then begin
result:=256-s+b;
end else result:=b-s;
end;

procedure mutatekeys(var key, key2: tkey; const idx: integer); // Mutate key
var i: integer;
begin
for i:=0 to 63 do begin
key[i]:=xsucc(key[i], (idx+key2[63-i]) mod 256);
end;
end;


procedure mutatekeys_64(var key: tkey; idx: integer); // Mutate key
var i,n: integer; nk: tkey;
begin
fillchar(nk,64,0);
for i:=0 to 63 do begin
nk[xsucc64(i,idx)]:=key[i];
end;
Move(nk,key,64);
end;



procedure mutatesubtabs(idx: integer); // Mutate key
var i,n,ni: integer; nk: tkey;
begin
fillchar(nk,64,0);
for i:=0 to 63 do begin
ni:=xsucc64(i,idx);
nk[ni]:=p_tab64[i];
p_dtab64[nk[ni]]:=ni;
end;
Move(nk,p_tab64,64);
end;


procedure mutatekeys_m(var key: tkey; const key_m: TKey); // Mutate key
var i: integer;
begin
for i:=0 to 63 do begin
key[i]:=bitrotf(key[i],key_m[i]);
end;
end;

procedure mutatebufs(var buf: array of byte; const idx, size: integer); // Mutate key
var i: integer;
begin
for i:=0 to size-1 do begin
buf[i]:=xsucc(buf[i],idx);
end;
end;


procedure mutatebufp(var buf: array of byte; const idx, size: integer); // Mutate key
var i: integer;
begin
for i:=0 to size-1 do begin
buf[i]:=xpred(buf[i],idx);
end;
end;


procedure mutatetables(idx: integer); // Mutate table
var i,nv: integer;
var Hash: TDCP_SHA512;
begin

for i:=0 to 255 do begin
nv:=xsucc(p_tab[i],idx);
p_tab[i]:=nv;
p_dtab[nv]:=i;
end;


end;

function tab_ex(const data, idx: integer): boolean; // Search byte in array
var i: integer;
begin
result:=false;
for i:=0 to idx-1 do begin
if p_tab[i]=data then begin
result:=true;
break;
end;
end;
end;

function tab_ex64(const data, idx: integer): boolean; // Search byte in array
var i: integer;
begin
result:=false;
for i:=0 to idx-1 do begin
if p_tab64[i]=data then begin
result:=true;
break;
end;
end;
end;


procedure initPT(var key: tkey;key2: Tkey); // Generate substtable


var Hash: TDCP_SHA512;i: integer; rnd,rnd2, rnd3, rnd4: array [0..63] of byte; p_xortab: array [0..255] of byte; p_cttab: array [0..255] of byte;
var idx: integer; ctr, ct: byte;
begin
fillchar(p_tab,256,0);
fillchar(p_dtab,256,0);
fillchar(p_cttab,256,0);
idx:=0;
move(key,p_tab,64);
move(key,p_tab[64],64);
move(key,p_tab[128],64);
move(key,p_tab[192],64);

ctr:=0;

ct:=key[0] xor key[63] xor key [13];

repeat


Hash:=TDCP_Sha512.Create(nil);
Hash.Init;
Hash.Update(p_tab,256);
fillchar(rnd,64,0);
Hash.Final(rnd);
Hash.Free;

Hash:=TDCP_Sha512.Create(nil);
Hash.Init;
Hash.Update(p_dtab,256);
fillchar(rnd2,64,0);
Hash.Final(rnd2);
Hash.Free;

XorBuff(@p_tab,@p_dtab,256,@p_xortab);

Hash:=TDCP_Sha512.Create(nil);
Hash.Init;
Hash.Update(p_xortab,256);
fillchar(rnd3,64,0);
Hash.Final(rnd3);
Hash.Free;

if ct<255 then inc(ct) else
begin
ct:=0;
mutatekeys(key,key2,ctr);
end;

ctr:= p_tab [ct] xor p_dtab[255-ct];

for i:=0 to 255 do begin
p_cttab[i]:=p_xortab[i] xor ctr;
end;


Hash:=TDCP_Sha512.Create(nil);
Hash.Init;
Hash.Update(p_cttab,256);
fillchar(rnd4,64,0);
Hash.Final(rnd4);
Hash.Free;



for i:=0 to 63 do begin

if not (tab_ex(rnd[i],idx)) then begin
p_tab[idx]:=rnd[i];
p_dtab[rnd[i]]:=idx;
inc(idx,1);
break;
end

else if not (tab_ex(rnd2[i],idx)) then begin
p_tab[idx]:=rnd2[i];
p_dtab[rnd2[i]]:=idx;
inc(idx,1);
break;
end

else

if not (tab_ex(rnd3[i],idx)) then begin
p_tab[idx]:=rnd3[i];
p_dtab[rnd3[i]]:=idx;
inc(idx,1);

break;
end

else

if not (tab_ex(rnd4[i],idx)) then begin
p_tab[idx]:=rnd4[i];
p_dtab[rnd4[i]]:=idx;
inc(idx,1);
break;
end;


end;



until (idx > 255);

end;

procedure fix64 (var x: TKey);
var i: integer;
begin
for i:=0 to 63 do begin
case x[i] of
0..63: {none};
64..127: x[i]:=x[i]-64;
128..191: x[i]:=x[i]-128;
192..255: x[i]:=x[i]-192;

end;

end;

end;


procedure initPT64(var key: tkey;key2: Tkey); // Generate substtable


var Hash: TDCP_SHA512;i: integer; rnd,rnd2, rnd3, rnd4: TKey; p_xortab64: TKey; p_cttab64: TKey;
var idx: integer; ctr, ct: byte;
begin
fillchar(p_tab64,64,0);
fillchar(p_dtab64,64,0);
fillchar(p_cttab64,64,0);
idx:=0;
move(key,p_tab64,64);

ctr:=0;

ct:=key[0] xor key[63] xor key [13];

repeat


Hash:=TDCP_Sha512.Create(nil);
Hash.Init;
Hash.Update(p_tab64,64);
fillchar(rnd,64,0);
Hash.Final(rnd);
Hash.Free;
Fix64(rnd);


Hash:=TDCP_Sha512.Create(nil);
Hash.Init;
Hash.Update(p_dtab64,64);
fillchar(rnd2,64,0);
Hash.Final(rnd2);
Hash.Free;
Fix64(rnd2);


XorBuff(@p_tab64,@p_dtab64,64,@p_xortab64);

Hash:=TDCP_Sha512.Create(nil);
Hash.Init;
Hash.Update(p_xortab64,64);
fillchar(rnd3,64,0);
Hash.Final(rnd3);
Hash.Free;
Fix64(rnd3);

if ct<63 then inc(ct) else
begin
ct:=0;
mutatekeys(key,key2,ctr);
end;

ctr:= p_tab64 [ct] xor p_dtab64[63-ct];

for i:=0 to 63 do begin
p_cttab64[i]:=p_xortab64[i] xor ctr;
end;


Hash:=TDCP_Sha512.Create(nil);
Hash.Init;
Hash.Update(p_cttab64,64);
fillchar(rnd4,64,0);
Hash.Final(rnd4);
Hash.Free;
Fix64(rnd4);



for i:=0 to 63 do begin

if not (tab_ex64(rnd[i],idx)) then begin
p_tab64[idx]:=rnd[i];
p_dtab64[rnd[i]]:=idx;
inc(idx,1);
break;
end

else if not (tab_ex64(rnd2[i],idx)) then begin
p_tab64[idx]:=rnd2[i];
p_dtab64[rnd2[i]]:=idx;
inc(idx,1);
break;
end

else

if not (tab_ex64(rnd3[i],idx)) then begin
p_tab64[idx]:=rnd3[i];
p_dtab64[rnd3[i]]:=idx;
inc(idx,1);

break;
end

else

if not (tab_ex64(rnd4[i],idx)) then begin
p_tab64[idx]:=rnd4[i];
p_dtab64[rnd4[i]]:=idx;
inc(idx,1);
break;
end;


end;



until (idx > 63);


end;




procedure DecryptBlock (ciphertext, dest: pointer;  size: integer; var key : TKey; var key2: TKey; var key3: TKey; key_m: TKey);
var
   ti : Integer;
   ct, ct2: array of byte;
   c1, c2, wkey, wkey2, c3, c4: word;
   o,b: byte;
begin

   mutatekeys_64(key_m, getbitssum64(key2));
   mutatekeys_m(key3,key_m);
   mutatesubtabs(getbitssum64(key3));

    wkey2:=key3[40] xor key3[41] xor key3[42] xor key3[43] xor key3[44] xor key3[45] xor key3[46];
    c3:=key2[40] xor key2[41] xor key2[42] xor key2[43] xor key2[44];
    c4:=key[40] xor key[41] xor key[43] xor key[44] xor key[45];

   mutatekeys(key3, key2, (key[GetBitssum(key[30])+50]));
   mutatekeys(key, key2, (key3[GetBitssum(key3[30])+50]));
   mutatekeys(key2, key, (key[GetBitssum(key[0])]));

   wkey:=key3[30] xor key3[31] xor key3[32] xor key3[33] xor key3[34];
   c1:=key2[30] xor key2[31] xor key2[32] xor key2[33] xor key2[34];
   c2:=key[30] xor key[31];
   mutatetables(GetBitssum(Byte(WKey shr 8)));

   // ------------------------------------------------------- //

   SetLength(ct,size);
   Move(ciphertext^,ct[0],size);
   FillChar(Dest^,size,0);



   for ti := 0 to size-1 do begin
      PbyteArray(dest)[ti] := byte(  (ct[ti] + key3[ti]) mod 256 );
      PbyteArray(dest)[ti]:=xsucc(PbyteArray(dest)[ti],GetBitsSum(Key3[10+GetBitsSum(key3[8])]));
      PbyteArray(dest)[ti] := byte( (PbyteArray(dest)[ti] + key[ti]) mod 256);
      PbyteArray(dest)[ti]:=xpred(PbyteArray(dest)[ti],GetBitsSum(Key[31+GetBitsSum(key[31])]));
      PbyteArray(dest)[ti]:=xsucc(PbyteArray(dest)[ti],GetBitsSum(Key2[40+GetBitsSum(key2[40])]));
      PbyteArray(dest)[ti] := byte( PbyteArray(dest)[ti] + key2[ti]) mod 256;

      PbyteArray(dest)[ti] := bitrotb(PbyteArray(dest)[ti],GetBitsSum(Key[GetBitsSum(key[0])]));
      PbyteArray(dest)[ti] := bitrotf(PbyteArray(dest)[ti],GetBitsSum(Key3[GetBitsSum(key3[0])]));

      o := PbyteArray(dest)[ti];
      PbyteArray(dest)[ti] := (PbyteArray(dest)[ti] xor (wKey2 shr 8));
      wKey2 := Word ((O + wKey2) * C3 + C4);

      o := PbyteArray(dest)[ti];
      PbyteArray(dest)[ti] := (PbyteArray(dest)[ti] xor (wKey shr 8));
      wKey := Word ((O + wKey) * C1 + C2);
      PbyteArray(dest)[ti]:=p_dtab[PbyteArray(dest)[ti]];
      PbyteArray(dest)[ti]:=p_dtab[PbyteArray(dest)[ti]];

   end;





if size=64 then begin

SetLength(ct2,64);
FillChar(ct2[0],64,0);


for ti:=0 to 63 do begin
ct2[ti]:=PbyteArray(dest)[p_dtab64[ti]];
end;


Move(ct2[0],dest^,64);
end;




end;





procedure EncryptBlock (plaintext, dest: pointer;  size: integer; var key : TKey; var key2: TKey; var key3: TKey; key_m: TKey);
var
   ti : Integer;
   ct,ct2: array of byte;
   c1, c2, wkey, wkey2, c3, c4: word; b: byte;

begin

   mutatekeys_64(key_m, getbitssum64(key2));
   mutatekeys_m(key3,key_m);
   mutatesubtabs(getbitssum64(key3));

   wkey2:=key3[40] xor key3[41] xor key3[42] xor key3[43] xor key3[44] xor key3[45] xor key3[46];
   c3:=key2[40] xor key2[41] xor key2[42] xor key2[43] xor key2[44];
   c4:=key[40] xor key[41] xor key[43] xor key[44] xor key[45];

   mutatekeys(key3, key2, (key[GetBitssum(key[30])+50]));
   mutatekeys(key, key2, (key3[GetBitssum(key3[30])+50]));
   mutatekeys(key2, key, (key[GetBitssum(key[0])]));

   wkey:=key3[30] xor key3[31] xor key3[32] xor key3[33] xor key3[34];
   c1:=key2[30] xor key2[31] xor key2[32] xor key2[33] xor key2[34];
   c2:=key[30] xor key[31];
   mutatetables(GetBitssum(Byte(WKey shr 8)));

  // ------------------------------------------------------- //

   SetLength(ct,size);
   Move(plaintext^,ct[0],size);
   FillChar(Dest^,size,0);




if size=64 then begin
SetLength(ct2,64);
FillChar(ct2[0],64,0);


for ti:=0 to 63 do begin
ct2[ti]:=ct[p_tab64[ti]];
end;

Move(ct2[0],ct[0],size);
end;




   for ti := 0 to size-1 do begin
      ct[ti]:=p_tab[ct[ti]];
      ct[ti]:=p_tab[ct[ti]];
      ct[ti] := (ct[ti] xor (wKey shr 8));
      wKey := Word ((ct[ti] + wKey) * C1 + C2);

      ct[ti] := (ct[ti] xor (wKey2 shr 8));
      wKey2 := Word ((ct[ti] + wKey2) * C3 + C4);

      PbyteArray(dest)[ti] := bitrotf(ct[ti],GetBitsSum(Key[GetBitsSum(key[0])]));
      PbyteArray(dest)[ti] := bitrotb(PbyteArray(dest)[ti],GetBitsSum(Key3[GetBitsSum(key3[0])]));

      PbyteArray(dest)[ti]:=xpred(PbyteArray(dest)[ti],GetBitsSum(Key3[10+GetBitsSum(key3[8])]));
      PbyteArray(dest)[ti] := byte(  (PbyteArray(dest)[ti] - key3[ti]) mod 256 );
      PbyteArray(dest)[ti] := byte( (PbyteArray(dest)[ti] - key[ti]) mod 256);
      PbyteArray(dest)[ti]:=xsucc(PbyteArray(dest)[ti],GetBitsSum(Key[31+GetBitsSum(key[31])]));
      PbyteArray(dest)[ti]:=xpred(PbyteArray(dest)[ti],GetBitsSum(Key2[40+GetBitsSum(key2[40])]));
      PbyteArray(dest)[ti] := byte( PbyteArray(dest)[ti] - key2[ti]) mod 256;

end;
end;



function vgcrypt22 (fi,ft: string;skey: string;dir: byte; process: pprocessproc=nil): boolean;
var Hash2: TDCP_Haval; Hash: TDCP_SHA512;FileIn, FileOut: TFileStream; Buffer, Dest, IV, XB: array [0..63] of byte; Left, BlockSize: integer;  key, key2, key3, key_m: TKey;  i: integer;
begin
Hash:=TDCP_Sha512.Create(nil);
Hash.Init;
Hash.UpdateStr(skey);
Hash.Final(key);
Hash.Free;

Hash2:=TDCP_Haval.Create(nil);
Hash2.Init;
Hash2.UpdateStr(skey);
Hash2.Final(key2);
Hash2.Free;

Hash2:=TDCP_Haval.Create(nil);
Hash2.Init;
Hash2.Update(key,64);
Hash2.Final(key2[32]);
Hash2.Free;

Hash:=TDCP_Sha512.Create(nil);
Hash.Init;
Hash.Update(key2,64);
Hash.Final(key2);
Hash.Free;


move(key,key3,32);
move(key2[32],key3[32],32);

Hash:=TDCP_Sha512.Create(nil);
Hash.Init;
Hash.Update(key3,64);
Hash.Final(key3);
Hash.Free;

Hash:=TDCP_Sha512.Create(nil);
Hash.Init;
Hash.Update(key3,64);
Hash.Final(key_m);
Hash.Free;

xorbuff(@key3,@key2,64,@key3);

  FileIn := TFileStream.Create(fi,fmOpenRead or fmShareDenyWrite);
  FileOut := TFileStream.Create(ft, fmCreate);
  Left := FileIn.Size;
  FillChar(Buffer,64,0);
  FillChar(Dest,64,0);
  FillChar(XB,64,0);

move(key, iv, 64);

for i:=0 to 63 do begin
key_m[i]:=GetBitsSum(key_m[i]);
end;

initpt(key,key2);
initpt64(key3,key);


DecryptBlock(@iv, @iv,64,key,key2, key3, key_m);



  repeat
if left<64 then blocksize:=left else blocksize:=64;
  FileIn.Read(Buffer, blocksize);

if dir=1 then
begin

XorBuff(@buffer,@iv,blocksize,@dest);



EncryptBlock(@Dest,@Dest,blocksize,key,key2, key3, key_m);


Move(dest,iv,blocksize);
end else begin


Move(Buffer,XB,blocksize);



DecryptBlock(@Buffer,@Buffer,blocksize,key,key2, key3, key_m);



XorBuff(@buffer,@iv,blocksize,@dest);
Move(XB,IV,blocksize);
end;


  FileOut.Write(Dest, blocksize);
if process<>nil then begin
TProcessproc(process)(blocksize);
end;
  dec(left,blocksize);
until left<=0;


FileIn.Destroy;
FileOut.Destroy;
result:=true;
end;


end.
