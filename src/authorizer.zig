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

pub const PartialValue = union(enum) {
    value: Value,
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

    fn asBool(self: @This()) !bool {
        return switch (self) {
            .literal => |l| switch (l) {
                .bool => |b| b,
                else => error.EvalError,
            },
            else => error.EvalError,
        };
    }
};

test "Value.asBool" {
    // only Expr.Literal boolean values are valid
    try std.testing.expectError(error.EvalError, Value.literal(Expr.Literal.entity(EntityUID.init("User", "alice"))).asBool());
    try std.testing.expect(try Value.literal(Expr.Literal.boolean(true)).asBool());
}

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
        context: Context = .{},
        schema: ?Schema = null,
    };

    pub fn init() @This() {
        return .{};
    }

    pub fn isAuthorized(
        _: @This(),
        request: Request,
        policySet: PolicySet,
        entities: Entities,
    ) Response {
        // see //https://github.com/cedar-policy/cedar/blob/fdcd70375c838be589e586392c0f95c623b9a78d/cedar-policy-core/src/authorizer.rs#L93
        // todo compute response from policy tests
        const eval = Evaluator.init(request, entities);
        for (policySet.policies) |p| {
            const result = eval.evaluate(p) catch {
                // todo communicate error
                return .{ .decision = .deny };
            };
            return .{ .decision = if (result) .allow else .deny };
        }
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
        return PartialValue.value(Value.literal(Expr.Literal.entity(self.request.principal)));
    }

    fn evalAction(self: @This()) PartialValue {
        return PartialValue.value(Value.literal(Expr.Literal.entity(self.request.action)));
    }

    fn evalResource(self: @This()) PartialValue {
        return PartialValue.value(Value.literal(Expr.Literal.entity(self.request.resource)));
    }

    fn evalContext(_: @This()) PartialValue {
        // todo: impl me
        return PartialValue.residual(Expr.unknown());
    }

    fn partialInterpret(self: @This(), expr: Expr) !PartialValue {
        // https://github.com/cedar-policy/cedar/blob/67131d64bb80cfa9cc861e999ede365d1bcbb26a/cedar-policy-core/src/evaluator.rs#L279
        // https://github.com/cedar-policy/cedar/blob/67131d64bb80cfa9cc861e999ede365d1bcbb26a/cedar-policy-core/src/evaluator.rs#L279
        return switch (expr) {
            .literal => |v| PartialValue.value(Value.literal(v)),
            .variable => |v| switch (v) {
                .principal => self.evalPrincipal(),
                .action => self.evalAction(),
                .resource => self.evalResource(),
                .context => self.evalContext(),
            },
            .pattern => |v| blk: {
                std.debug.print("pattern {any}\n", .{v});
                break :blk PartialValue.residual(Expr.unknown());
            },
            .slot => |v| blk: {
                std.debug.print("slot {any}\n", .{v});
                break :blk PartialValue.residual(Expr.unknown());
            },
            .ite => |v| blk: {
                std.debug.print("if/then/else {any}\n", .{v});
                break :blk PartialValue.residual(Expr.unknown());
            },
            .@"and" => |v| blk: {
                std.debug.print("and {any}\n", .{v});
                break :blk switch (try self.partialInterpret(v.left.*)) {
                    // full eval
                    .value => |ll| if (try ll.asBool())
                        switch (try self.partialInterpret(v.right.*)) {
                            .value => |rr| PartialValue.value(Value.literal(Expr.Literal.boolean(try rr.asBool()))),
                            .residual => |rr| PartialValue.residual(Expr.add(Expr.literal(Expr.Literal.boolean(true)), rr)),
                        }
                    else
                        PartialValue.value(Value.literal(Expr.Literal.boolean(false))), // short circut here
                    // partial eval case, return left expr
                    .residual => |ll| PartialValue.residual(ll),
                };
            },
            .@"or" => |v| blk: {
                std.debug.print("or {any}\n", .{v});
                break :blk PartialValue.residual(Expr.unknown());
            },
            .unary => |v| blk: {
                std.debug.print("unary {any}\n", .{v});
                break :blk PartialValue.residual(Expr.unknown());
            },
            .binary => |v| blk: {
                std.debug.print("binary {any}\n", .{v});
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
                        .residual => |bb| return PartialValue.residual(Expr.binary(op, aa, bb)),
                    },
                };
                std.debug.print("a {any} b {any}\n", .{ va, vb });
                switch (v.op) {
                    .eq => {
                        const eq = std.meta.eql(va, vb);
                        std.debug.print("are these eq? {any}\n", .{eq});
                        break :blk PartialValue.value(
                            Value.literal(
                                Expr.Literal.boolean(eq),
                            ),
                        );
                    },
                    .lt => {},
                    .lte => {},
                    .add => {},
                    .sub => {},
                    .mul => {},
                    .in => {},
                    .contains => {},
                    .contains_all => {},
                    .contains_any => {},
                }
                break :blk PartialValue.residual(Expr.unknown());
            },
            .is => |v| blk: {
                std.debug.print("is {any}\n", .{v});
                break :blk PartialValue.residual(Expr.unknown());
            },
            .unknown => PartialValue.residual(expr), // the unknown case
        };
    }

    //fn eval_if(self: @This(), i: Expr, t: Expr, e: Expr)
};

// test "Value meta eq" {
//     try std.testing.expect(
//         std.meta.eql(
//             Value.literal(Expr.Literal.entity(EntityUID.init("foo", "bar"))),
//             Value.literal(Expr.Literal.entity(EntityUID.init("foo", "bar"))),
//         ),
//     );
// }
