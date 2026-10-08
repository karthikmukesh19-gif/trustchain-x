import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

interface Point {
  date: string;
  projects: number;
}

const shortDay = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", timeZone: "UTC" });

function label(isoDate: string): string {
  const date = new Date(`${isoDate}T00:00:00Z`);
  return Number.isNaN(date.getTime()) ? isoDate : shortDay.format(date);
}

/** Projects registered per day (UTC). One series, so no legend is needed. */
export function RegistrationsChart({ data }: { data: Point[] }) {
  const rows = data.map((point) => ({ ...point, label: label(point.date) }));
  const max = Math.max(1, ...rows.map((row) => row.projects));
  return (
    <div className="h-52 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={rows} margin={{ top: 8, right: 8, bottom: 0, left: -18 }}>
          <CartesianGrid stroke="#dfdcd3" strokeDasharray="2 4" vertical={false} />
          <XAxis
            dataKey="label"
            tick={{ fontSize: 11, fill: "#646b78" }}
            tickLine={false}
            axisLine={{ stroke: "#dfdcd3" }}
            interval="preserveStartEnd"
            minTickGap={24}
          />
          <YAxis
            allowDecimals={false}
            domain={[0, max]}
            tick={{ fontSize: 11, fill: "#646b78" }}
            tickLine={false}
            axisLine={false}
            width={44}
          />
          <Tooltip
            cursor={{ fill: "#f5f4ef" }}
            formatter={(value: unknown) => [String(value), "Projects registered"]}
            contentStyle={{ borderRadius: 6, border: "1px solid #dfdcd3", fontSize: 12 }}
          />
          <Bar dataKey="projects" fill="#0f766e" radius={[3, 3, 0, 0]} maxBarSize={28} isAnimationActive={false} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
