from easyauth.router import EasyAuthAPIRouter

hr_router = EasyAuthAPIRouter.create(prefix="/hr", tags=["hr"])


@hr_router.get("/")
async def hr_root():
    return "hr_root"


@hr_router.get("/data")
async def hr_data():
    return "hr_data"


print("hr setup")
