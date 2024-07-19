const std = @import("std");
const PolicySet = @import("root.zig").PolicySet;
const Policy = @import("types.zig").Policy;
const Context = @import("root.zig").Context;
const Schema = @import("root.zig").Schema;
const Entities = @import("root.zig").Entities;
const EntityUID = @import("root.zig").EntityUID;
const Expr = @import("types.zig").Expr;
const SlotEnv = @import("types.zig").SlotEnv;
const CendarType = @import("types.zig").CedarType;

/// Represents an evalution outcome which is either a value or residual expression
pub const PartialValue = union(enum) {
    /// a successfully evaluated value
    value: Value,
    /// an incomplete result an evaluation
    residual: Expr,

    /// declares a resolved value
    fn value(v: Value) @This() {
        return .{ .value = v };
    }

    /// declares an unresolved or partially evaluated expression
    fn residual(e: Expr) @This() {
        return .{ .residual = e };
    }
};

/// represents a resolved value from an expression evaluation
pub const Value = union(enum) {
    literal: Expr.Literal,
    set: CendarType.Set,
    record: CendarType.Record,

    fn literal(v: Expr.Literal) @This() {
        return .{ .literal = v };
    }

    fn set(v: CendarType.Set) @This() {
        return .{ .set = v };
    }

    fn record(v: CendarType.Record) @This() {
        return .{ .record = v };
    }

    /// returns a bool value if this is a literal bool
    /// otherwise return an EvalError
    fn asBool(self: @This()) !bool {
        return switch (self) {
            .literal => |l| switch (l) {
                .bool => |v| v,
                else => |v| blk: {
                    std.debug.print("expected literal bool but recieved a literal {s}\n", .{@tagName(v)});
                    break :blk error.EvalError;
                },
            },
            else => |v| blk: {
                std.debug.print("expected literal but recieved a {s}\n", .{@tagName(v)});
                break :blk error.EvalError;
            },
        };
    }

    /// returns an i64 value if this is a literal i64
    /// otherwise return an EvalError
    fn asLong(self: @This()) !i64 {
        return switch (self) {
            .literal => |l| switch (l) {
                .long => |v| v,
                else => |v| blk: {
                    std.debug.print("expected literal long but recieved a literal {s}\n", .{@tagName(v)});
                    break :blk error.EvalError;
                },
            },
            else => |v| blk: {
                std.debug.print("expected literal value but recieved a {s}\n", .{@tagName(v)});
                break :blk error.EvalError;
            },
        };
    }

    /// returns an EntityUID value if this is a literal EntityUID
    /// otherwise return an EvalError
    fn asEntity(self: @This()) !EntityUID {
        return switch (self) {
            .literal => |l| switch (l) {
                .entity => |v| v,
                else => error.EvalError,
            },
            else => error.EvalError,
        };
    }

    // std.meta.eq is shallow and auto hashing does not support  net.Address
    // https://github.com/ziglang/zig/issues/19003
    fn eql(self: @This(), other: @This()) bool {
        return switch (self) {
            .literal => |v| switch (other) {
                .literal => |vv| v.eql(vv),
                else => false,
            },
            else => false,
        };
    }
};

test "Value.asBool" {
    // only Expr.Literal boolean values are valid
    try std.testing.expectError(error.EvalError, Value.literal(Expr.Literal.entity(EntityUID.init("User", "alice"))).asBool());
    try std.testing.expect(try Value.literal(Expr.Literal.boolean(true)).asBool());
}

test "Value.asLong" {
    // only Expr.Literal long values are valid
    try std.testing.expectError(error.EvalError, Value.literal(Expr.Literal.entity(EntityUID.init("User", "alice"))).asLong());
    try std.testing.expectEqual(1, try Value.literal(Expr.Literal.long(1)).asLong());
}

test "Value.asEntity" {
    // only Expr.Literal entity values are valid
    try std.testing.expectError(error.EvalError, Value.literal(Expr.Literal.boolean(true)).asEntity());
    try std.testing.expect(
        std.meta.eql(
            EntityUID.init("User", "alice"),
            (try Value.literal(Expr.Literal.entity(EntityUID.init("User", "alice"))).asEntity()),
        ),
    );
}

test "Value.eql" {
    for ([_]struct { l: Value, r: Value, expect: bool }{
        .{ .l = Value.literal(Expr.Literal.entity(EntityUID.init("foo", "bar"))), .r = Value.literal(Expr.Literal.entity(EntityUID.init("foo", "bar"))), .expect = true },
        .{ .l = Value.literal(Expr.Literal.entity(EntityUID.init("foo", "bar"))), .r = Value.literal(Expr.Literal.entity(EntityUID.init("foo", "baz"))), .expect = false },
    }) |case| {
        const eq = case.l.eql(case.r);
        std.testing.expect(if (case.expect) eq else !eq) catch |err| {
            std.debug.print(
                "expected {any} when comparing {any} and {any}",
                .{ case.expect, case.l, case.r },
            );
            return err;
        };
    }
}

/// The primary interface for answering authorization questions
pub const Authorizer = struct {
    pub const Response = struct {
        /// outcome of authorization query
        pub const Decision = enum {
            allow,
            deny,
        };
        /// the authorization decision, defaults to deny
        decision: Decision = .deny,
        // todo: add diagnostics
    };

    /// per-request authorization query inputs
    pub const Request = struct {
        principal: EntityUID,
        action: EntityUID,
        resource: EntityUID,
        context: Context = .{},
        schema: ?Schema = null,
    };

    pub fn init() @This() {
        return .{};
    }

    /// Returns a Response containing information about the outcome of for a given
    /// authorization request
    pub fn isAuthorized(
        _: @This(),
        request: Request,
        policySet: PolicySet,
        entities: Entities,
    ) Response {
        // see https://github.com/cedar-policy/cedar/blob/fdcd70375c838be589e586392c0f95c623b9a78d/cedar-policy-core/src/authorizer.rs#L93
        const eval = Evaluator.init(request, entities);
        for (policySet.policies) |p| {
            // todo: aggregate answers to from all policies before
            // coming to a decision
            const result = eval.evaluate(p) catch |e| {
                // todo communicate error through response type
                std.debug.print("eval error: {any}\n", .{e});
                return .{ .decision = .deny };
            };
            return .{ .decision = if (result) .allow else .deny };
        }
        // default to deny
        return .{ .decision = .deny };
    }
};

const PartialResponse = struct {};

// internal implementation
const Evaluator = struct {
    request: Authorizer.Request,
    entities: Entities,

    fn init(request: Authorizer.Request, entities: Entities) @This() {
        return .{ .request = request, .entities = entities };
    }

    /// evaluates an expression, returns true if this results an a literal `true` result
    fn evaluate(self: @This(), policy: Policy) !bool {
        // todo: pass policy.env
        return (try self.interpret(policy.condition())).asBool();
    }

    /// translates a partial interpreter result to an error
    /// and returns the value of resolved expressions
    fn interpret(self: @This(), expr: Expr) !Value {
        return switch (try self.partialInterpret(expr)) {
            .value => |v| v,
            .residual => error.EvalError,
        };
    }

    fn evalPrincipal(self: @This()) PartialValue {
        std.debug.print("evaling principal to a partial value {}\n", .{self.request.principal});
        return PartialValue.value(Value.literal(Expr.Literal.entity(self.request.principal)));
    }

    fn evalAction(self: @This()) PartialValue {
        std.debug.print("evaling action to a partial value {}\n", .{self.request.action});
        return PartialValue.value(Value.literal(Expr.Literal.entity(self.request.action)));
    }

    fn evalResource(self: @This()) PartialValue {
        std.debug.print("evaling resource to a partial value {}\n", .{self.request.resource});
        return PartialValue.value(Value.literal(Expr.Literal.entity(self.request.resource)));
    }

    fn partialInterpret(self: @This(), expr: Expr) !PartialValue {
        // https://github.com/cedar-policy/cedar/blob/67131d64bb80cfa9cc861e999ede365d1bcbb26a/cedar-policy-core/src/evaluator.rs#L279
        std.debug.print("partially interpretting expr: {any}\n", .{expr});
        return switch (expr) {
            .literal => |v| blk: {
                std.debug.print("yielding literal {any}\n", .{v});
                break :blk PartialValue.value(Value.literal(v));
            },
            .variable => |v| switch (v) {
                .principal => self.evalPrincipal(),
                .action => self.evalAction(),
                .resource => self.evalResource(),
                .context => return error.TODO,
            },
            .pattern => |v| {
                std.debug.print("pattern {any}\n", .{v});
                return error.TODO;
            },
            .slot => |v| {
                std.debug.print("slot {any}\n", .{v});
                return error.TODO;
            },
            .ite => |v| {
                std.debug.print("if/then/else {any}\n", .{v});
                return error.TODO;
            },
            .@"and" => |v| blk: {
                std.debug.print("and {any}\n", .{v});
                break :blk switch (try self.partialInterpret(v.left.*)) {
                    // full eval
                    .value => |ll| if (try ll.asBool())
                        switch (try self.partialInterpret(v.right.*)) {
                            .value => |rr| PartialValue.value(Value.literal(Expr.Literal.boolean(try rr.asBool()))),
                            .residual => |rr| PartialValue.residual(Expr.@"and"(Expr.literal(Expr.Literal.boolean(true)), rr)),
                        }
                    else
                        PartialValue.value(Value.literal(Expr.Literal.boolean(false))), // doesn't matter what v.right is, short circut here
                    // partial eval case, return left expr
                    .residual => |ll| PartialValue.residual(ll),
                };
            },
            .@"or" => |v| blk: {
                std.debug.print("or {any}\n", .{v});
                break :blk switch (try self.partialInterpret(v.left.*)) {
                    // full eval
                    .value => |ll| if (try ll.asBool()) PartialValue.value(Value.literal(Expr.Literal.boolean(false))) // doesn't matter what v.right is, short circut here
                    else switch (try self.partialInterpret(v.right.*)) {
                        .value => |rr| PartialValue.value(Value.literal(Expr.Literal.boolean(try rr.asBool()))),
                        .residual => |rr| PartialValue.residual(Expr.@"or"(Expr.literal(Expr.Literal.boolean(false)), rr)),
                    },
                    // partial eval case
                    .residual => |ll| PartialValue.residual(Expr.@"or"(ll, v.right.*)),
                };
            },
            .unary => |v| {
                std.debug.print("unary {any}\n", .{v});
                return error.TODO;
            },
            .binary => |v| blk: {
                //std.debug.print("binary {any}\n", .{v});
                const a = try self.partialInterpret(v.arg1.*);
                const b = try self.partialInterpret(v.arg2.*);
                const op = v.op;
                const va, const vb = switch (a) {
                    .value => |aa| switch (b) {
                        .value => |bb| .{ aa, bb },
                        .residual => return error.TODO,
                    },
                    .residual => |aa| switch (b) {
                        .value => return error.TODO,
                        .residual => |bb| {
                            std.debug.print("returning residual for binary op {}\n", .{op});
                            return PartialValue.residual(Expr.binary(op, aa, bb));
                        },
                    },
                };
                switch (v.op) {
                    .eq => break :blk PartialValue.value(
                        Value.literal(
                            Expr.Literal.boolean(va.eql(vb)),
                        ),
                    ),
                    .lt, .lte, .add, .sub, .mul => {
                        const la = try va.asLong();
                        const lb = try vb.asLong();
                        break :blk PartialValue.value(
                            Value.literal(switch (v.op) {
                                .lt => Expr.Literal.boolean(la == lb),
                                .lte => Expr.Literal.boolean(la <= lb),
                                .add => Expr.Literal.long(try std.math.add(i64, la, lb)),
                                .sub => Expr.Literal.long(try std.math.sub(i64, la, lb)),
                                .mul => Expr.Literal.long(try std.math.mul(i64, la, lb)),
                                else => unreachable, // expect cases are covered above
                            }),
                        );
                    },
                    .in => {},
                    .contains => {},
                    .contains_all => {},
                    .contains_any => {},
                }
                std.debug.print("returning fall through for uninplemented binary op {}\n", .{op});
                return error.TODO;
            },
            .is => |v| blk: {
                std.debug.print("is {any}\n", .{v});
                break :blk switch (try self.partialInterpret(v.expr.*)) {
                    .value => |vv| PartialValue.value(
                        Value.literal(
                            Expr.Literal.boolean(std.mem.eql(u8, (try vv.asEntity()).type, v.type)),
                        ),
                    ),
                    .residual => |vv| PartialValue.residual(
                        Expr.isEntityType(vv, v.type),
                    ),
                };
            },
            .unknown => PartialValue.residual(expr), // the unknown case
        };
    }
};

test "Evaluator.evaluate" {
    if (true) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const eval = Evaluator.init(.{
        .principal = EntityUID.init("User", "a"),
        .action = EntityUID.init("Action", "b"),
        .resource = EntityUID.init("Resource", "c"),
    }, .{});
    var policySet = try @import("root.zig").parse(allocator,
        \\permit(
        \\    principal == User::"a",
        \\    action == Action::"b",
        \\    resource == Resource::"c"
        \\);
    );
    defer policySet.deinit();
    try std.testing.expect(eval.evaluate(policySet.policies[0]) catch |err| {
        std.debug.print("expected true but error was returned {any}\n", .{err});
        return err;
    });
}
