from easyauth.router import EasyAuthAPIRouter

finance_router = EasyAuthAPIRouter.create(prefix="/finance", tags=["finance"])


@finance_router.get("/")
async def finance_root():
    return "fiance_root"


@finance_router.get("/data")
async def finance_data():
    return "finance_data"


print("finance setup")
