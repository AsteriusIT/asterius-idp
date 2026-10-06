import * as React from "react"
import { cn } from "@/lib/utils"
import { Separator as SeparatorPrimitive } from "@base-ui/react/separator"

function Separator({
  className,
  orientation = "horizontal",
  decorative = true,
  ...props
}: Omit<React.ComponentProps<typeof SeparatorPrimitive>, "className"> & {
  className?: string
  decorative?: boolean
}) {
  return (
    <SeparatorPrimitive
      data-slot="separator"
      role={decorative ? "presentation" : "separator"}
      orientation={orientation}
      className={cn(
        "shrink-0 bg-border data-horizontal:h-px data-horizontal:w-full data-vertical:h-full data-vertical:w-px",
        className
      )}
      {...props}
    />
  )
}

export { Separator }
