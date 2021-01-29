"""
Purpose:
Increments current Pypi version by .001

Usage: 
    pip3 download easy-auth && ls easy_auth*.whl | sed 's/-/" "/g' | awk '{print "(" $2 ")"}' |  python3 python/easyauth/easyauth/nextbuild.py
"""
if __name__=='__main__':
    import sys
    version = sys.stdin.readline().rstrip()
    if '(' in version and ')' in version:
        right_i = version.index('(')
        left_i = version.index(')')
        version = version[right_i+2:left_i-1]
        print(f"{float(version)+0.001:.3f}")