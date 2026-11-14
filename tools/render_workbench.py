import json, os
from PIL import Image, ImageDraw, ImageFont
ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
r=json.load(open(os.path.join(ROOT,'docs','report.json'),encoding='utf-8'))
W,H=1280,900; BG=(13,17,23); FG=(215,222,232); DIM=(139,152,171); AC=(158,203,255); GR=(126,231,135)
F="C:/Windows/Fonts/consola.ttf"
img=Image.new('RGB',(W,H),BG); d=ImageDraw.Draw(img)
f=ImageFont.truetype(F,14); fb=ImageFont.truetype(F,18); fs=ImageFont.truetype(F,12)
d.text((24,16),"moonbin — in-browser RE workbench (pure wasm)",font=fb,fill=AC)
d.text((24,44),f"{r['format']}  machine={r['machine']}  entry={r['entry']}  base={r['base']}  size={r['size']}B  entropy={r['entropy']}",font=f,fill=FG)
d.text((W-320,20),"zero FFI - same code as native",font=fs,fill=GR)
# left: sections + entropy bars
y=80; d.text((24,y),"Sections / entropy",font=f,fill=AC); y+=24
se={s['name']:s['entropy'] for s in r.get('section_entropy',[])}
for s in r['sections']:
    e=se.get(s['name'],0)
    d.text((24,y),f"{s['name']:<8} {s['flags']:<3}",font=fs,fill=FG)
    d.rectangle([140,y+3,340,y+11],fill=(34,48,74))
    d.rectangle([140,y+3,140+int(200*e/8),y+11],fill=(63,185,80) if e<6 else (210,153,34))
    d.text((348,y),f"{e:.2f}",font=fs,fill=DIM); y+=20
# left lower: imports sample
y+=10; d.text((24,y),f"Imports ({len(r['imports'])})",font=f,fill=AC); y+=22
for i in r['imports'][:8]:
    d.text((24,y),f"{i['library']}!{i['name']}",font=fs,fill=FG); y+=18
# right: disasm with source
x=560; y=80; d.text((x,y),"Disassembly (.text) + DWARF source",font=f,fill=AC); y+=24
src={l['addr']:f"{l['file']}:{l['line']}" for l in r.get('dwarf',{}).get('lines',[])}
for i in r['disasm']['insns'][:24]:
    d.text((x,y),i['addr'],font=fs,fill=DIM)
    d.text((x+70,y),i['mnemonic'],font=fs,fill=GR)
    d.text((x+130,y),i['op_str'][:34],font=fs,fill=FG)
    d.text((x+430,y),src.get(i['addr'],''),font=fs,fill=AC); y+=19
# CFG strip bottom
y=H-160; d.text((24,y),"Control-flow graph (decoded window)",font=f,fill=AC)
ins=r['disasm']['insns']; 
import re
def addr(s): return int(s,16)
leaders={addr(ins[0]['addr'])}
for k,i in enumerate(ins):
    if i['mnemonic'].startswith('j') or i['mnemonic']=='ret':
        if k+1<len(ins): leaders.add(addr(ins[k+1]['addr']))
        t=re.search(r'0x[0-9a-f]+',i['op_str'])
        if t: leaders.add(addr(t.group(0)))
starts=sorted(a for a in leaders if any(addr(i['addr'])==a for i in ins))
bx=24; by=y+26
for bi,s in enumerate(starts[:10]):
    d.rectangle([bx,by,bx+110,by+34],outline=(58,74,99),fill=(26,35,50))
    d.text((bx+6,by+4),hex(s),font=fs,fill=AC)
    d.text((bx+6,by+18),"block",font=fs,fill=DIM)
    if bi+1<min(10,len(starts)): d.line([bx+110,by+17,bx+124,by+17],fill=DIM)
    bx+=124
img.save(os.path.join(ROOT,'docs','workbench.png'))
print("wrote workbench.png")
