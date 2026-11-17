import concurrent.futures
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from experiment import LocalRouter, Rejected

class BoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='boundary-tests-')
        self.base=Path(self.tmp.name); self.alice=self.base/'alice'; self.bob=self.base/'bob'
        self.alice.mkdir(); self.bob.mkdir(); self.outside=self.base/'outside.txt'; self.outside.write_text('not authorized')
        self.router=LocalRouter({'alice':self.alice,'bob':self.bob})
        self.call={'tool':'store_note','args':{'path':'a.txt','content':'draft'}}
    def tearDown(self): self.router.close(); self.tmp.cleanup()
    def read(self,path='a.txt',principal='alice'):
        return self.router.execute(principal,{'tool':'read_note','args':{'path':path}})
    def store(self,call=None):
        call=call or self.call; token=self.router.approve_store('alice',call['args'])
        return self.router.execute('alice',call,approval_token=token)
    def test_unknown_tool(self):
        for name in ('shell','send_email','delete_note',1,None):
            with self.subTest(name=name),self.assertRaises(Rejected): self.router.execute('alice',{'tool':name,'args':{'path':'a.txt'}})
    def test_exact_top_schema(self):
        for call in ({**self.call,'approved':True},{'args':{}},[]):
            with self.subTest(call=call),self.assertRaises(Rejected): self.router.execute('alice',call)
    def test_exact_argument_schema(self):
        for args in ({**self.call['args'],'approved':True},{**self.call['args'],'root':str(self.base)},{'path':'a.txt'},None):
            with self.subTest(args=args),self.assertRaises(Rejected): self.router.execute('alice',{'tool':'store_note','args':args})
    def test_content_types_and_limits(self):
        for content in (True,1,None,{},'x'*(LocalRouter.MAX_BYTES+1),'\ud800'):
            with self.subTest(kind=type(content)),self.assertRaises(Rejected): self.router.approve_store('alice',{'path':'a.txt','content':content})
    def test_path_types_and_syntax(self):
        for path in (Path('a.txt'),'../outside.txt','/tmp/x','a/../b','./a','a//b','a/','a\\b','%2e%2e/outside.txt','','a\x00b','a'*257):
            with self.subTest(path=path),self.assertRaises(Rejected): self.read(path)
    def test_unknown_principal(self):
        with self.assertRaises(Rejected): self.read(principal='mallory')
    def test_principal_scoped_read(self):
        (self.alice/'a.txt').write_text('alice only')
        with self.assertRaises(Rejected): self.read(principal='bob')
        (self.bob/'a.txt').write_text('bob only')
        self.assertEqual(self.read()['content'],'alice only'); self.assertEqual(self.read(principal='bob')['content'],'bob only')
    def test_symlink_file_outside(self):
        (self.alice/'a.txt').symlink_to(self.outside)
        with self.assertRaises(Rejected): self.read()
        with self.assertRaises(Rejected): self.router.approve_store('alice',self.call['args'])
        self.assertEqual(self.outside.read_text(),'not authorized')
    def test_symlink_directory_outside(self):
        (self.alice/'notes').symlink_to(self.base,target_is_directory=True)
        with self.assertRaises(Rejected): self.read('notes/outside.txt')
    def test_symlink_directory_inside(self):
        (self.alice/'real').mkdir(); (self.alice/'notes').symlink_to(self.alice/'real',target_is_directory=True)
        with self.assertRaises(Rejected): self.router.approve_store('alice',{'path':'notes/x.txt','content':'x'})
    def test_symlink_after_validation(self):
        (self.alice/'a.txt').write_text('safe'); original=self.router._open_parent
        def swap(principal,parts):
            (self.alice/'a.txt').unlink(); (self.alice/'a.txt').symlink_to(self.outside); return original(principal,parts)
        with patch.object(self.router,'_open_parent',side_effect=swap),self.assertRaises(Rejected): self.read()
    def test_regular_nested_directory(self):
        (self.alice/'notes').mkdir(); self.store({'tool':'store_note','args':{'path':'notes/x.txt','content':'中文'}})
        self.assertEqual(self.read('notes/x.txt')['content'],'中文')
    def test_unapproved_store(self):
        with self.assertRaises(Rejected): self.router.execute('alice',self.call)
        self.assertFalse((self.alice/'a.txt').exists())
    def test_no_overwrite(self):
        self.store()
        with self.assertRaises(Rejected): self.router.approve_store('alice',self.call['args'])
        self.assertEqual((self.alice/'a.txt').read_text(),'draft')
    def test_approval_content_binding(self):
        token=self.router.approve_store('alice',self.call['args']); changed={'tool':'store_note','args':{'path':'a.txt','content':'changed'}}
        with self.assertRaises(Rejected): self.router.execute('alice',changed,approval_token=token)
        self.assertEqual(self.router.execute('alice',self.call,approval_token=token)['status'],'stored')
    def test_approval_path_binding(self):
        token=self.router.approve_store('alice',self.call['args']); changed={'tool':'store_note','args':{'path':'b.txt','content':'draft'}}
        with self.assertRaises(Rejected): self.router.execute('alice',changed,approval_token=token)
        self.assertFalse((self.alice/'b.txt').exists())
    def test_approval_principal_binding(self):
        token=self.router.approve_store('alice',self.call['args'])
        with self.assertRaises(Rejected): self.router.execute('bob',self.call,approval_token=token)
        self.assertFalse((self.bob/'a.txt').exists())
    def test_one_shot_approval(self):
        token=self.router.approve_store('alice',self.call['args']); self.router.execute('alice',self.call,approval_token=token)
        with self.assertRaises(Rejected): self.router.execute('alice',self.call,approval_token=token)
    def test_forged_approval(self):
        with self.assertRaises(Rejected): self.router.execute('alice',self.call,approval_token='invented')
    def test_read_schema_independent_of_store_capability(self):
        token=self.router.approve_store('alice',self.call['args'])
        with self.assertRaises(Rejected): self.router.execute('alice',{'tool':'read_note','args':self.call['args']},approval_token=token)
    def test_destination_race_after_approval(self):
        token=self.router.approve_store('alice',self.call['args']); (self.alice/'a.txt').write_text('raced in')
        with self.assertRaises(Rejected): self.router.execute('alice',self.call,approval_token=token)
        self.assertEqual((self.alice/'a.txt').read_text(),'raced in'); self.assertEqual(list(self.alice.glob('.pending-*')),[])
    def test_destination_symlink_race(self):
        token=self.router.approve_store('alice',self.call['args']); original=os.link
        def race(*args,**kwargs): (self.alice/'a.txt').symlink_to(self.outside); return original(*args,**kwargs)
        with patch('experiment.os.link',side_effect=race),self.assertRaises(Rejected): self.router.execute('alice',self.call,approval_token=token)
        self.assertEqual(self.outside.read_text(),'not authorized'); self.assertEqual(list(self.alice.glob('.pending-*')),[])
    def test_two_approvals_same_destination_no_clobber(self):
        calls=[{'tool':'store_note','args':{'path':'a.txt','content':c}} for c in ('first','second')]
        tokens=[self.router.approve_store('alice',c['args']) for c in calls]
        def attempt(pair):
            call,token=pair
            try: return self.router.execute('alice',call,approval_token=token)['status']
            except Rejected: return 'rejected'
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool: results=list(pool.map(attempt,zip(calls,tokens)))
        self.assertCountEqual(results,['stored','rejected']); self.assertIn((self.alice/'a.txt').read_text(),('first','second')); self.assertEqual(list(self.alice.glob('.pending-*')),[])
    def test_parallel_same_token_once(self):
        token=self.router.approve_store('alice',self.call['args'])
        def attempt(_):
            try: return self.router.execute('alice',self.call,approval_token=token)['status']
            except Rejected: return 'rejected'
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool: results=list(pool.map(attempt,range(8)))
        self.assertEqual(results.count('stored'),1); self.assertEqual(results.count('rejected'),7)
    def test_io_failure_consumes_approval_and_cleans_temp(self):
        token=self.router.approve_store('alice',self.call['args'])
        with patch('experiment.os.link',side_effect=OSError('synthetic failure')),self.assertRaises(Rejected): self.router.execute('alice',self.call,approval_token=token)
        with self.assertRaises(Rejected): self.router.execute('alice',self.call,approval_token=token)
        self.assertFalse((self.alice/'a.txt').exists()); self.assertEqual(list(self.alice.glob('.pending-*')),[])
    def test_nonregular_large_binary_missing_reads(self):
        (self.alice/'directory').mkdir(); os.mkfifo(self.alice/'fifo'); (self.alice/'big').write_bytes(b'a'*(LocalRouter.MAX_BYTES+1)); (self.alice/'binary').write_bytes(b'\xff\xfe')
        for name in ('directory','fifo','big','binary','missing'):
            with self.subTest(name=name),self.assertRaises(Rejected): self.read(name)
    def test_empty_note(self):
        self.store({'tool':'store_note','args':{'path':'empty.txt','content':''}}); self.assertEqual(self.read('empty.txt')['content'],'')
    def test_exact_size_limit_and_private_file_mode(self):
        self.store({'tool':'store_note','args':{'path':'limit.txt','content':'a'*LocalRouter.MAX_BYTES}})
        self.assertEqual(len(self.read('limit.txt')['content']),LocalRouter.MAX_BYTES)
        self.assertEqual((self.alice/'limit.txt').stat().st_mode & 0o777,0o600)
    def test_argument_snapshot_is_not_mutable_after_fingerprint(self):
        token=self.router.approve_store('alice',self.call['args']); original=self.router._open_parent
        def mutate(principal,parts):
            self.call['args']['content']='not approved'; return original(principal,parts)
        with patch.object(self.router,'_open_parent',side_effect=mutate):
            self.router.execute('alice',self.call,approval_token=token)
        self.assertEqual((self.alice/'a.txt').read_text(),'draft')

if __name__=='__main__': unittest.main()
