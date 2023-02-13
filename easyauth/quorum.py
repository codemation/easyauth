import asyncio
import os
import random
import string
import uuid


def get_random_string(length):
    letters = string.ascii_lowercase
    return "".join(random.choice(letters) for i in range(length))


async def quorum_setup(cache):

    member_id = str(uuid.uuid4())
    cache.member_id = member_id
    os.environ["member_id"] = member_id

    with open("quorum.txt", "w") as q:
        q.write(member_id)

    # waiting for other members to join quorum
    await asyncio.sleep(2)

    cache.leader = False

    # elect leader - first member to join
    with open("quorum.txt", "r") as q:
        if q.readline().rstrip() == member_id:
            cache.leader = True
