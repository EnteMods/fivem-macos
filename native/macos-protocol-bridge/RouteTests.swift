import Foundation

@main
struct RouteTests {
    static func main() {
        let prefix = "fivem://accept-auth?payload="
        let samples: [(Bool, String)] = [
            (true, prefix + "synthetic"),
            (true, prefix + "synthetic%2Bvalue%2Fonly%3D"),
            (true, prefix + "synthetic%26value%23only"),
            (true, prefix + "synthetic+value="),
            (true, prefix + String(repeating: "x", count: AuthRoute.maximumBytes - prefix.utf8.count)),
            (false, "http://accept-auth?payload=synthetic"),
            (false, "https://accept-auth?payload=synthetic"),
            (false, "fivem://connect?payload=synthetic"),
            (false, "fivem://accept-auth.evil?payload=synthetic"),
            (false, "fivem://user@accept-auth?payload=synthetic"),
            (false, "fivem://user:password@accept-auth?payload=synthetic"),
            (false, "fivem://accept-auth:80?payload=synthetic"),
            (false, "fivem://accept-auth/?payload=synthetic"),
            (false, "fivem://accept-auth/path?payload=synthetic"),
            (false, prefix + "synthetic#fragment"),
            (false, prefix + "synthetic#"),
            (false, "fivem://accept-auth"),
            (false, "fivem://accept-auth?payload"),
            (false, prefix),
            (false, prefix + "synthetic&payload=duplicate"),
            (false, prefix + "synthetic&other=value"),
            (false, "fivem://accept-auth?other=synthetic&payload=second"),
            (false, "fivem://accept-auth?%70ayload=synthetic"),
            (false, prefix + "synthetic%"),
            (false, prefix + "synthetic%2"),
            (false, prefix + "synthetic%2Z"),
            (false, prefix + "synthetic value"),
            (false, prefix + "synthetic\nvalue"),
            (false, prefix + "synthetic\0value"),
            (false, prefix + String(repeating: "x", count: AuthRoute.maximumBytes - prefix.utf8.count + 1)),
            (false, prefix + String(repeating: "é", count: AuthRoute.maximumBytes / 2))
        ]
        var failures = 0
        for (index, sample) in samples.enumerated() {
            if AuthRoute.accepts(sample.1) != sample.0 {
                failures += 1
                print("ROUTE_CASE_FAILURE=\(index)")
            }
        }
        print("ROUTE_CASES=\(samples.count)")
        print("ROUTE_FAILURES=\(failures)")
        exit(failures == 0 ? 0 : 1)
    }
}
