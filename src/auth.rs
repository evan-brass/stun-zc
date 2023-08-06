pub enum StunAuth<'i> {
	NoAuth,
	Static {
		username: &'i str,
		realm: Option<&'i str>,
		password: &'i str
	},
	Dynamic (&'i dyn Fn(&str, Option<&str>) -> Option<&'i str>)
}
