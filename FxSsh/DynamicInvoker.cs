using FxSsh.Messages;
using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Reflection;

namespace FxSsh
{
    public static class DynamicInvoker
    {
        static Dictionary<string, Action<IDynamicInvoker, Message>> _cache =
            new Dictionary<string, Action<IDynamicInvoker, Message>>();

        public static void InvokeHandleMessage(this IDynamicInvoker instance, Message message)
        {
            var instype = instance.GetType();
            var msgtype = message.GetType();

            var key = instype.Name + '!' + msgtype.Name;
            var action = _cache.ContainsKey(key) ? _cache[key] : null;
            if (action == null)
            {
                var method = instance.GetType()
                    .GetMethod("HandleMessage",
                    BindingFlags.NonPublic | BindingFlags.Instance,
                    null,
                    new[] { message.GetType() },
                    null);
                var insparam = Expression.Parameter(typeof(IDynamicInvoker));
                var msgparam = Expression.Parameter(typeof(Message));
                var call = Expression.Call(
                    Expression.Convert(insparam, instype),
                    method,
                    Expression.Convert(msgparam, msgtype));
                action = Expression.Lambda<Action<IDynamicInvoker, Message>>(call, insparam, msgparam).Compile();
                _cache[key] = action;
            }
            action(instance, message);
        }
    }

    public interface IDynamicInvoker { }
}
