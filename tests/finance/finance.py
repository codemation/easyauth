# finance setup
async def setup(router):

    @router.get('/')
    async def finance_root():
        return f"fiance_root"
    
    @router.get('/data')
    async def finance_data():
        return f"finance_data"