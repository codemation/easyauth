# marketing setup
async def setup(router):

    @router.get('/')
    async def marketing_root():
        return f"marketing_root"
    
    @router.get('/data')
    async def marketing_data():
        return f"marketing_data"