from easyauth.router import EasyAuthAPIRouter

hr_router = EasyAuthAPIRouter.create(prefix='/hr', tags=['hr'])

@hr_router.get('/')
async def hr_root():
    return f"hr_root"

@hr_router.get('/data')
async def hr_data():
    return f"hr_data"

print(f"hr setup")