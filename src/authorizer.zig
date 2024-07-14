const PolicySet = @import("root.zig").PolicySet;
const Context = @import("root.zig").Context;
const Schema = @import("root.zig").Schema;
const Entities = @import("root.zig").Entities;
const EntityUID = @import("root.zig").EntityUID;

pub const Authorizer = struct {
    pub const Response = struct {
        pub const Decision = enum {
            allow,
            deny,
        };
        /// the authorization decision, defaults to deny
        decision: Decision = .deny,
    };

    pub const Request = struct {
        principal: EntityUID,
        action: EntityUID,
        resource: EntityUID,
        context: Context,
        schema: ?Schema = null,
    };

    pub fn init() @This() {
        return .{};
    }

    pub fn isAuthorized(
        _: @This(),
        _: Request,
        _: PolicySet,
        _: Entities,
    ) Response {
        // todo
        return .{};
    }
};
