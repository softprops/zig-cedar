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

    /// return bool value if this is a literal bool
    /// otherwise return an EvalError
    fn asBool(self: @This()) !bool {
        return switch (self) {
            .literal => |l| switch (l) {
                .bool => |v| v,
                else => error.EvalError,
            },
            else => error.EvalError,
        };
    }

    /// return i64 value if this is a literal i64
    /// otherwise return an EvalError
    fn asLong(self: @This()) !i64 {
        return switch (self) {
            .literal => |l| switch (l) {
                .long => |v| v,
                else => error.EvalError,
            },
            else => error.EvalError,
        };
    }

    /// return EntityUID value if this is a literal EntityUID
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
};

test "Value.asBool" {
    // only Expr.Literal boolean values are valid
    try std.testing.expectError(error.EvalError, Value.literal(Expr.Literal.entity(EntityUID.init("User", "alice"))).asBool());
    try std.testing.expect(try Value.literal(Expr.Literal.boolean(true)).asBool());
}

test "Value meta.eq" {
    for ([_]struct { l: Value, r: Value, expect: bool }{
        .{ .l = Value.literal(Expr.Literal.entity(EntityUID.init("foo", "bar"))), .r = Value.literal(Expr.Literal.entity(EntityUID.init("foo", "bar"))), .expect = true },
        .{ .l = Value.literal(Expr.Literal.entity(EntityUID.init("foo", "bar"))), .r = Value.literal(Expr.Literal.entity(EntityUID.init("foo", "baz"))), .expect = false },
    }) |case| {
        const eq = std.meta.eql(case.l, case.r);
        std.testing.expect(if (case.expect) eq else !eq) catch |err| {
            std.debug.print("expected {any} when comparing {any} and {any}", .{ case.expect, case.l, case.r });
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
                switch (v.op) {
                    .eq => {
                        const eq = std.meta.eql(va, vb);
                        std.debug.print("are {any} and {any} meta.eq? {any}\n", .{ va, vb, eq });
                        break :blk PartialValue.value(
                            Value.literal(
                                Expr.Literal.boolean(eq),
                            ),
                        );
                    },
                    .lt, .lte, .add, .sub, .mul => {
                        const la = try va.asLong();
                        const lb = try vb.asLong();
                        break :blk switch (v.op) {
                            .lt => PartialValue.value(
                                Value.literal(
                                    Expr.Literal.boolean(la == lb),
                                ),
                            ),
                            .lte => PartialValue.value(
                                Value.literal(
                                    Expr.Literal.boolean(la <= lb),
                                ),
                            ),
                            .add => PartialValue.value(
                                Value.literal(
                                    Expr.Literal.long(try std.math.add(i64, la, lb)),
                                ),
                            ),
                            .sub => PartialValue.value(
                                Value.literal(
                                    Expr.Literal.long(try std.math.sub(i64, la, lb)),
                                ),
                            ),
                            .mul => PartialValue.value(
                                Value.literal(
                                    Expr.Literal.long(try std.math.mul(i64, la, lb)),
                                ),
                            ),
                            else => unreachable, // expect cases are covered above
                        };
                    },
                    .in => {},
                    .contains => {},
                    .contains_all => {},
                    .contains_any => {},
                }
                break :blk PartialValue.residual(Expr.unknown());
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

    //fn eval_if(self: @This(), i: Expr, t: Expr, e: Expr)
};
