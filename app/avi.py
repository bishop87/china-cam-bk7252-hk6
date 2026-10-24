"""Small video-only MJPEG AVI export of the frames actually received during playback."""
import struct
from protocol import jpeg_size

def chunk(tag,data):
    return tag+struct.pack('<I',len(data))+data+(b'\0' if len(data)%2 else b'')

def export_avi(frames, fps=10):
    if not frames:raise ValueError('Nessun fotogramma disponibile')
    width,height=jpeg_size(frames[0])
    largest=max(map(len,frames))
    avih=struct.pack('<14I',int(1000000/fps),int(largest*fps),0,16,len(frames),0,1,largest,width,height,0,0,0,0)
    strh=struct.pack('<4s4sIHH8I4h',b'vids',b'MJPG',0,0,0,0,1000,round(fps*1000),0,len(frames),largest,0xffffffff,0,0,0,width,height)
    strf=struct.pack('<IiiHH4sIiiII',40,width,height,1,24,b'MJPG',width*height*3,0,0,0,0)
    hdrl=chunk(b'LIST',b'hdrl'+chunk(b'avih',avih)+chunk(b'LIST',b'strl'+chunk(b'strh',strh)+chunk(b'strf',strf)))
    movie=[];index=[];offset=4
    for frame in frames:
        block=chunk(b'00dc',frame);movie.append(block)
        index.append(struct.pack('<4sIII',b'00dc',16,offset,len(frame)));offset+=len(block)
    return chunk(b'RIFF',b'AVI '+hdrl+chunk(b'LIST',b'movi'+b''.join(movie))+chunk(b'idx1',b''.join(index)))
