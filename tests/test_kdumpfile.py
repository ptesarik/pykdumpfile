import unittest
import kdumpfile
import sys

def get_attr_item(attr, key):
    return attr[key]

def get_ostype_attr(attr):
    return attr.addrxlat.ostype

def iter_search_subkey(attr_dir, name):
    found = False
    for key in attr_dir:
        if key == name:
            found = True
    return found

class TestContext(unittest.TestCase):
    err_msg = 'Custom error message'
    err_msg2 = 'Another error'
    def test_err(self):
        ctx = kdumpfile.Context()
        self.assertIsNone(ctx.get_err())
        ctx.err(kdumpfile.OK, self.err_msg)
        self.assertIsNone(ctx.get_err())
        ctx.err(kdumpfile.ERR_NOTIMPL, self.err_msg)
        self.assertEqual(ctx.get_err(), self.err_msg)
        ctx.err(kdumpfile.ERR_NOTIMPL, self.err_msg2)
        self.assertEqual(ctx.get_err(), '{}: {}'.format(self.err_msg2, self.err_msg))
        ctx.clear_err()
        self.assertIsNone(ctx.get_err())

    def test_attr(self):
        ctx = kdumpfile.Context()
        attr = ctx.attr

        self.assertIsNone(attr.get(kdumpfile.ATTR_OSTYPE))
        self.assertRaises(KeyError, get_attr_item, attr, kdumpfile.ATTR_OSTYPE)
        self.assertRaises(AttributeError, get_ostype_attr, attr)

        # unset directories can be instantiated but not iterated
        self.assertTrue('ostype' in attr.addrxlat)
        self.assertRaises(kdumpfile.NoDataError, iter_search_subkey, attr.addrxlat, 'ostype')

        # unknown OS type fails early and does not change the attribute value
        self.assertRaises(NotImplementedError, attr.__setitem__, kdumpfile.ATTR_OSTYPE, 'unknown')
        self.assertRaises(KeyError, get_attr_item, attr, kdumpfile.ATTR_OSTYPE)

        attr[kdumpfile.ATTR_OSTYPE] = 'linux'
        self.assertEqual(attr.get(kdumpfile.ATTR_OSTYPE), 'linux')
        self.assertEqual(attr[kdumpfile.ATTR_OSTYPE], 'linux')
        self.assertEqual(attr.addrxlat.ostype, 'linux')

        self.assertTrue(iter_search_subkey(attr.addrxlat, 'ostype'))

        del attr.addrxlat.ostype
        self.assertIsNone(attr.get(kdumpfile.ATTR_OSTYPE))
        self.assertRaises(KeyError, get_attr_item, attr, kdumpfile.ATTR_OSTYPE)
        self.assertRaises(AttributeError, get_ostype_attr, attr)

        # unset attributes are contained but skipped in iteration
        self.assertFalse(iter_search_subkey(attr.addrxlat, 'ostype'))

        attr.addrxlat.ostype = 'linux'
        self.assertEqual(attr.get(kdumpfile.ATTR_OSTYPE), 'linux')
        self.assertEqual(attr[kdumpfile.ATTR_OSTYPE], 'linux')
        self.assertEqual(attr.addrxlat.ostype, 'linux')

if __name__ == '__main__':
    unittest.main()
