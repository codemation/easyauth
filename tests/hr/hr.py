# hr setup
async def setup(router):

    @router.get('/')
    async def hr_root():
        return f"hr_root"
    
    @router.get('/data')
    async def hr_data():
        return f"hr_data"