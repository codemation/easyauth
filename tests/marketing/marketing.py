from easyauth.router import EasyAuthAPIRouter

marketing_router = EasyAuthAPIRouter.create(prefix='/marketing', tags=['marketing'])

@marketing_router.get('/')
async def marketing_root():
    return f"marketing_root"

@marketing_router.get('/data')
async def marketing_data():
    return f"marketing_data"

print(f"marketing setup")