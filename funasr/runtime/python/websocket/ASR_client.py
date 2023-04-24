
# import websocket #区别服务端这里是 websocket-client库
import time
import websockets
import asyncio
# import threading
import argparse
import json

parser = argparse.ArgumentParser()
parser.add_argument("--host",
                    type=str,
                    default="localhost",
                    required=False,
                    help="host ip, localhost, 0.0.0.0")
parser.add_argument("--port",
                    type=int,
                    default=10095,
                    required=False,
                    help="grpc server port")
parser.add_argument("--chunk_size",
                    type=int,
                    default=300,
                    help="ms")
parser.add_argument("--audio_in",
                    type=str,
                    default=None,
                    help="audio_in")

args = parser.parse_args()

# voices = asyncio.Queue()
from queue import Queue
voices = Queue()
    
# 其他函数可以通过调用send(data)来发送数据，例如：
async def record_microphone():
    import pyaudio
    #print("2")
    global voices 
    FORMAT = pyaudio.paInt16
    CHANNELS = 1
    RATE = 16000
    CHUNK = int(RATE / 1000 * args.chunk_size)

    p = pyaudio.PyAudio()

    stream = p.open(format=FORMAT,
                    channels=CHANNELS,
                    rate=RATE,
                    input=True,
                    frames_per_buffer=CHUNK)

    while True:

        data = stream.read(CHUNK)
        
        voices.put(data)
        #print(voices.qsize())

        await asyncio.sleep(0.01)

# 其他函数可以通过调用send(data)来发送数据，例如：
async def record_from_scp():
    global voices
    if args.audio_in.endswith(".scp"):
        f_scp = open(args.audio_in)
        wavs = f_scp.readlines()
    else:
        wavs = [args.audio_in]
    for wav in wavs:
        wav_splits = wav.strip().split()
        wav_path = wav_splits[1] if len(wav_splits) > 1 else wav_splits[0]
        bytes = open(wav_path, "rb")
        bytes = bytes.read()
        
        stride = int(args.chunk_size/1000*16000*2)
        chunk_num = (len(bytes)-1)//stride + 1
        for i in range(chunk_num):
            beg = i*stride
            data_chunk = bytes[beg:beg+stride]
            voices.put(data_chunk)
            # print("data_chunk: ", len(data_chunk))
            # print(voices.qsize())
        
            await asyncio.sleep(args.chunk_size/1000)
     

async def ws_send():
    global voices
    global websocket
    print("started to sending data!")
    while True:
        while not voices.empty():
            data = voices.get()
            voices.task_done()
            try:
                await websocket.send(data) # 通过ws对象发送数据
            except Exception as e:
                print('Exception occurred:', e)
            await asyncio.sleep(0.01)
        await asyncio.sleep(0.01)



async def message():
    global websocket
    while True:
        try:
            meg = await websocket.recv()
            meg = json.loads(meg)
            print(meg)
        except Exception as e:
            print("Exception:", e)          
        


async def ws_client():
    global websocket # 定义一个全局变量ws，用于保存websocket连接对象
    # uri = "ws://11.167.134.197:8899"
    uri = "ws://{}:{}".format(args.host, args.port)
    #ws = await websockets.connect(uri, subprotocols=["binary"]) # 创建一个长连接
    async for websocket in websockets.connect(uri, subprotocols=["binary"], ping_interval=None):
        if args.audio_in is not None:
            task = asyncio.create_task(record_from_scp()) # 创建一个后台任务录音
        else:
            task = asyncio.create_task(record_microphone())  # 创建一个后台任务录音
        task2 = asyncio.create_task(ws_send()) # 创建一个后台任务发送
        task3 = asyncio.create_task(message()) # 创建一个后台接收消息的任务
        await asyncio.gather(task, task2, task3)


asyncio.get_event_loop().run_until_complete(ws_client()) # 启动协程
asyncio.get_event_loop().run_forever()
