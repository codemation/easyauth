import os, uuid
import asyncio

import random, string
def get_random_string(length):
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str

async def quorum_setup(cache): 

    member_id = str(uuid.uuid4())
    cache.member_id = member_id
    os.environ['member_id'] = member_id

    with open('quorum.txt', 'w') as q:
        q.write(member_id)

    # waiting for other members to join quorum
    await asyncio.sleep(2)

    cache.leader = False

    # elect leader - first member to join
    with open('quorum.txt', 'r') as q:
        if q.readline().rstrip() == member_id:
            cache.leader = True

    if cache.leader:
        RPC_SECRET = get_random_string(12)
        with open('.rpc_secret', 'w') as secret:
            secret.write(RPC_SECRET)
            os.environ['RPC_SECRET'] = RPC_SECRET
            await asyncio.sleep(0.3)
    else:
        await asyncio.sleep(2)
        with open('.rpc_secret', 'r') as secret:
            RPC_SECRET = secret.readline().rstrip()
        os.environ['RPC_SECRET'] = RPC_SECRET